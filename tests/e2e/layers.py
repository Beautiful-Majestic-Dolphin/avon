"""The layer table. Data only — the runner interprets it.

A layer is a slice of Avon that can be judged on its own. Layers are brought up
cumulatively because layer 3 needs layer 2's certificates and enrolled devices;
isolating them would mean rebuilding the world for no benefit.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Layer:
    name: str
    marker: str
    kind: Literal["cargo", "compose"]
    profile: str | None = None
    services: tuple[str, ...] = ()
    description: str = ""


LAYERS: list[Layer] = [
    Layer("l0", "l0", "cargo", description="build"),
    Layer("l1", "l1", "cargo", description="crypto"),
    Layer(
        "l2", "l2", "compose", profile="l2",
        services=("postgres", "redis", "ca", "control"),
        description="control plane",
    ),
    Layer(
        "l3", "l3", "compose", profile="l3",
        services=("gateway", "agent-a", "agent-b", "target-http", "target-ssh",
                  "target-pg", "target-udp"),
        description="data plane",
    ),
    Layer("l4", "l4", "compose", profile="l4", description="policy"),
    Layer(
        "l5", "l5", "compose", profile="l5",
        services=("swtpm", "agent-tpm", "agent-clone"),
        description="device trust",
    ),
    Layer(
        "lnet", "lnet", "compose", profile="lnet",
        services=("nat-a", "nat-b"),
        description="network conditions",
    ),
]

LAYER_NAMES = [layer.name for layer in LAYERS]
