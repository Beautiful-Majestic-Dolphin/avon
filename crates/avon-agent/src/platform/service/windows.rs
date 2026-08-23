//! Windows services.
//!
//! One service, running as LocalSystem. Unlike Linux and macOS there is no
//! privileged helper: the helper exists to hand a kernel TUN descriptor to an
//! unprivileged process, and a WinTun session cannot be adopted by another
//! process at all. The service is registered but not started — an agent with no
//! identity would crash-loop — so `install` registers and stops there.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const AGENT_SERVICE: &str = "avon-agent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

type Result<T> = std::result::Result<T, windows_service::Error>;

fn restart_after(delay: Duration) -> ServiceFailureActions {
    ServiceFailureActions {
        // A day without a failure resets the counter; a service that has been
        // healthy since yesterday should get the full three retries again.
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay,
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay,
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay,
            },
        ]),
    }
}

/// Register the service. `exe` is the absolute path to the agent binary; the
/// caller is expected to be elevated.
pub fn install(exe: &Path) -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let access = ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE;

    let agent_info = ServiceInfo {
        name: OsString::from(AGENT_SERVICE),
        display_name: OsString::from("AVON Agent"),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec![OsString::from("run"), OsString::from("--service")],
        dependencies: vec![],
        // LocalSystem: WinTun sessions cannot be handed to another process, so
        // the service that owns the adapter is the service that runs.
        account_name: None,
        account_password: None,
    };
    let agent_service = manager
        .create_service(&agent_info, access)
        .or_else(|_| manager.open_service(AGENT_SERVICE, access))?;
    agent_service.set_description("AVON post-quantum zero-trust network access agent.")?;
    agent_service.update_failure_actions(restart_after(Duration::from_secs(5)))?;
    agent_service.set_failure_actions_on_non_crash_failures(true)?;

    Ok(())
}

/// Stop and delete the service. A missing service is not an error: uninstall
/// has to be safe to run twice.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    for name in [AGENT_SERVICE] {
        let Ok(service) = manager.open_service(name, access) else {
            continue;
        };
        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
        let _ = service.delete();
    }
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service stopped with an error");
    }
}

/// The SCM entry point. Blocks until the service is stopped.
pub fn run_as_service() -> Result<()> {
    service_dispatcher::start(AGENT_SERVICE, ffi_service_main)
}

fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(mut tx) = shutdown_tx.lock() {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let handle = service_control_handler::register(AGENT_SERVICE, handler)?;
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;

    let result = tokio::runtime::Runtime::new()
        .map_err(windows_service::Error::Winapi)
        .and_then(|rt| {
            rt.block_on(async move {
                let shutdown = async {
                    let _ = shutdown_rx.await;
                    tracing::info!("service stop requested");
                };
                crate::run::run_agent(crate::run::RunOptions::default(), shutdown)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "agent exited with an error");
                        windows_service::Error::Winapi(std::io::Error::other(e.to_string()))
                    })
            })
        });

    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    result
}
