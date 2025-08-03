#!/bin/bash
#
# Local test runner for AWS V4 integration tests
# This script helps developers run AWS V4 tests locally with proper environment setup

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if environment variable is set
check_env() {
    local var_name=$1
    if [[ -z "${!var_name:-}" ]]; then
        return 1
    fi
    return 0
}

# Function to run tests with proper grouping
run_test() {
    local test_name=$1
    local test_function=$2
    
    echo ""
    echo "========================================="
    print_info "Running: $test_name"
    echo "========================================="
    
    if cargo test -p reqsign-aws-v4 $test_function --no-fail-fast -- --nocapture; then
        print_info "✅ $test_name PASSED"
    else
        print_error "❌ $test_name FAILED"
        return 1
    fi
}

# Main script
cd "$(dirname "$0")/.."

print_info "AWS V4 Local Test Runner"
echo ""

# Always run unit tests
print_info "Running unit tests (always run)..."
cargo test -p reqsign-aws-v4 --lib --no-fail-fast

# Check for integration test environment
if ! check_env "REQSIGN_AWS_V4_TEST" || [[ "$REQSIGN_AWS_V4_TEST" != "on" ]]; then
    print_warn "Integration tests are disabled (REQSIGN_AWS_V4_TEST != 'on')"
    print_info "To run integration tests, set up your environment:"
    echo ""
    echo "  # For signing tests:"
    echo "  export REQSIGN_AWS_V4_TEST=on"
    echo "  export REQSIGN_AWS_V4_ACCESS_KEY=your_access_key"
    echo "  export REQSIGN_AWS_V4_SECRET_KEY=your_secret_key"
    echo "  export REQSIGN_AWS_V4_REGION=us-east-1"
    echo "  export REQSIGN_AWS_V4_SERVICE=s3"
    echo "  export REQSIGN_AWS_V4_URL=https://your-bucket.s3.amazonaws.com"
    echo ""
    echo "  # For specific credential provider tests:"
    echo "  export REQSIGN_AWS_V4_TEST_ENV=on"
    echo "  export AWS_ACCESS_KEY_ID=your_key"
    echo "  export AWS_SECRET_ACCESS_KEY=your_secret"
    echo ""
    exit 0
fi

# Run signing tests
print_info "Running signing tests..."
run_test "Signing Tests" "signing::"

# Run credential provider tests based on environment
test_count=0
failed_count=0

# EnvCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_ENV" && [[ "$REQSIGN_AWS_V4_TEST_ENV" == "on" ]]; then
    if check_env "AWS_ACCESS_KEY_ID" && check_env "AWS_SECRET_ACCESS_KEY"; then
        ((test_count++))
        if ! run_test "EnvCredentialProvider" "test_env_credential_provider"; then
            ((failed_count++))
        fi
    else
        print_warn "Skipping EnvCredentialProvider test (AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set)"
    fi
fi

# ProfileCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_PROFILE" && [[ "$REQSIGN_AWS_V4_TEST_PROFILE" == "on" ]]; then
    ((test_count++))
    if ! run_test "ProfileCredentialProvider" "test_profile_credential_provider"; then
        ((failed_count++))
    fi
fi

# AssumeRoleCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_ASSUME_ROLE" && [[ "$REQSIGN_AWS_V4_TEST_ASSUME_ROLE" == "on" ]]; then
    if check_env "REQSIGN_AWS_V4_ASSUME_ROLE_ARN"; then
        ((test_count++))
        if ! run_test "AssumeRoleCredentialProvider" "test_assume_role_credential_provider"; then
            ((failed_count++))
        fi
    else
        print_warn "Skipping AssumeRoleCredentialProvider test (REQSIGN_AWS_V4_ASSUME_ROLE_ARN not set)"
    fi
fi

# AssumeRoleWithWebIdentityCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_WEB_IDENTITY" && [[ "$REQSIGN_AWS_V4_TEST_WEB_IDENTITY" == "on" ]]; then
    if check_env "AWS_ROLE_ARN" && check_env "AWS_WEB_IDENTITY_TOKEN_FILE"; then
        ((test_count++))
        if ! run_test "AssumeRoleWithWebIdentityCredentialProvider" "test_assume_role_with_web_identity_credential_provider"; then
            ((failed_count++))
        fi
    else
        print_warn "Skipping AssumeRoleWithWebIdentityCredentialProvider test (AWS_ROLE_ARN or AWS_WEB_IDENTITY_TOKEN_FILE not set)"
    fi
fi

# IMDSv2CredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_IMDS" && [[ "$REQSIGN_AWS_V4_TEST_IMDS" == "on" ]]; then
    ((test_count++))
    if ! run_test "IMDSv2CredentialProvider" "test_imds_v2_credential_provider"; then
        ((failed_count++))
    fi
fi

# ECSCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_ECS" && [[ "$REQSIGN_AWS_V4_TEST_ECS" == "on" ]]; then
    ((test_count++))
    if ! run_test "ECSCredentialProvider" "test_ecs_credential_provider"; then
        ((failed_count++))
    fi
fi

# SSOCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_SSO" && [[ "$REQSIGN_AWS_V4_TEST_SSO" == "on" ]]; then
    ((test_count++))
    if ! run_test "SSOCredentialProvider" "test_sso_credential_provider"; then
        ((failed_count++))
    fi
fi

# ProcessCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_PROCESS" && [[ "$REQSIGN_AWS_V4_TEST_PROCESS" == "on" ]]; then
    ((test_count++))
    if ! run_test "ProcessCredentialProvider" "test_process_credential_provider"; then
        ((failed_count++))
    fi
fi

# CognitoIdentityCredentialProvider
if check_env "REQSIGN_AWS_V4_TEST_COGNITO" && [[ "$REQSIGN_AWS_V4_TEST_COGNITO" == "on" ]]; then
    if check_env "REQSIGN_AWS_V4_COGNITO_IDENTITY_POOL_ID"; then
        ((test_count++))
        if ! run_test "CognitoIdentityCredentialProvider" "test_cognito_identity_credential_provider"; then
            ((failed_count++))
        fi
    else
        print_warn "Skipping CognitoIdentityCredentialProvider test (REQSIGN_AWS_V4_COGNITO_IDENTITY_POOL_ID not set)"
    fi
fi

# Summary
echo ""
echo "========================================="
print_info "Test Summary"
echo "========================================="
echo "Unit tests: PASSED"
echo "Signing tests: PASSED"
echo "Credential provider tests: $((test_count - failed_count))/$test_count passed"

if [[ $failed_count -gt 0 ]]; then
    print_error "Some tests failed!"
    exit 1
else
    print_info "All tests passed!"
fi