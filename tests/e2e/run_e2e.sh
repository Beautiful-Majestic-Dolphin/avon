#!/bin/bash
# AVON End-to-End Test Runner
#
# This script builds and runs the complete E2E test suite in Docker Compose.
#
# Usage:
#   ./run_e2e.sh              # Run all tests
#   ./run_e2e.sh --quick      # Run only fast tests
#   ./run_e2e.sh --keep       # Keep containers running after tests
#   ./run_e2e.sh --build      # Force rebuild of images
#   ./run_e2e.sh scenarios/test_full_flow.py  # Run specific test file

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COMPOSE_FILE="docker-compose.e2e.yml"
PROJECT_NAME="avon-e2e"
RESULTS_DIR="./results"
TIMEOUT=600  # 10 minutes max

# Parse arguments
QUICK_MODE=false
KEEP_CONTAINERS=false
FORCE_BUILD=false
TEST_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            TEST_ARGS="-m 'not slow'"
            shift
            ;;
        --keep)
            KEEP_CONTAINERS=true
            shift
            ;;
        --build)
            FORCE_BUILD=true
            shift
            ;;
        --help|-h)
            echo "AVON E2E Test Runner"
            echo ""
            echo "Usage: $0 [OPTIONS] [PYTEST_ARGS]"
            echo ""
            echo "Options:"
            echo "  --quick     Run only fast tests (exclude slow tests)"
            echo "  --keep      Keep containers running after tests"
            echo "  --build     Force rebuild of Docker images"
            echo "  --help      Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Run all tests"
            echo "  $0 --quick                            # Run fast tests only"
            echo "  $0 scenarios/test_full_flow.py        # Run specific test file"
            echo "  $0 -k 'test_enrollment'               # Run tests matching pattern"
            exit 0
            ;;
        *)
            TEST_ARGS="$TEST_ARGS $1"
            shift
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    if [ "$KEEP_CONTAINERS" = false ]; then
        log_info "Cleaning up containers..."
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v --remove-orphans 2>/dev/null || true
    else
        log_info "Keeping containers running (use 'docker compose -f $COMPOSE_FILE -p $PROJECT_NAME down -v' to clean up)"
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Create results directory
mkdir -p "$RESULTS_DIR"

# Change to script directory
cd "$(dirname "$0")"

log_info "Starting AVON E2E Tests"
log_info "========================"

# Check Docker
if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not available"
    exit 1
fi

# Build images
if [ "$FORCE_BUILD" = true ]; then
    log_info "Force rebuilding Docker images..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" build --no-cache
else
    log_info "Building Docker images (use --build to force rebuild)..."
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" build
fi

# Start infrastructure services first
log_info "Starting infrastructure services..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d postgres redis

# Wait for infrastructure
log_info "Waiting for infrastructure to be ready..."
sleep 5

# Check PostgreSQL
for i in {1..30}; do
    if docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" exec -T postgres pg_isready -U avon &> /dev/null; then
        log_info "PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "PostgreSQL failed to start"
        exit 1
    fi
    sleep 1
done

# Check Redis
for i in {1..30}; do
    if docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" exec -T redis redis-cli ping &> /dev/null; then
        log_info "Redis is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Redis failed to start"
        exit 1
    fi
    sleep 1
done

# Start control plane services
log_info "Starting control plane services..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d gateway auth ca pulse policy-engine admin-api

# Wait for services
log_info "Waiting for control plane services to be ready..."
sleep 15

# Start agents
log_info "Starting test agents..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d agent-1 agent-2

# Wait for agents
log_info "Waiting for agents to be ready..."
sleep 10

# Show running containers
log_info "Running containers:"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps

# Run tests
log_info "Running E2E tests..."
log_info "Test arguments: $TEST_ARGS"

# Run the test container
set +e  # Don't exit on test failure
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" run \
    --rm \
    -e PYTEST_ARGS="$TEST_ARGS" \
    test-runner \
    python -m pytest scenarios/ \
        -v \
        --tb=short \
        --junitxml=/app/results/results.xml \
        --timeout=$TIMEOUT \
        $TEST_ARGS

TEST_EXIT_CODE=$?
set -e

# Copy results
log_info "Copying test results..."
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" cp \
    test-runner:/app/results/. "$RESULTS_DIR/" 2>/dev/null || true

# Show results summary
if [ -f "$RESULTS_DIR/results.xml" ]; then
    log_info "Test results saved to $RESULTS_DIR/results.xml"
fi

# Show logs on failure
if [ $TEST_EXIT_CODE -ne 0 ]; then
    log_error "Tests failed with exit code $TEST_EXIT_CODE"
    log_info "Showing recent logs from services..."

    echo ""
    echo "=== Gateway Logs ==="
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs --tail=50 gateway 2>/dev/null || true

    echo ""
    echo "=== Auth Logs ==="
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs --tail=50 auth 2>/dev/null || true

    echo ""
    echo "=== Agent-1 Logs ==="
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs --tail=50 agent-1 2>/dev/null || true

    echo ""
    echo "=== Agent-2 Logs ==="
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs --tail=50 agent-2 2>/dev/null || true
fi

# Final status
echo ""
if [ $TEST_EXIT_CODE -eq 0 ]; then
    log_info "=========================================="
    log_info "  All E2E tests passed!"
    log_info "=========================================="
else
    log_error "=========================================="
    log_error "  E2E tests failed (exit code: $TEST_EXIT_CODE)"
    log_error "=========================================="
fi

exit $TEST_EXIT_CODE
