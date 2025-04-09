# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

#!/bin/bash

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
TEMPLATE_NAME="outposts_nm_resiliency_infrastructure_stack.yaml"

# Function to print error messages
error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

# Function to print warning/info messages
info() {
    echo -e "${YELLOW}$1${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    local missing_prereqs=()

    # Check for AWS CLI
    if ! command -v aws >/dev/null 2>&1; then
        missing_prereqs+=("AWS CLI")
    fi

    # Check for AWS credentials
    if ! aws sts get-caller-identity >/dev/null 2>&1; then
        missing_prereqs+=("AWS credentials")
    fi

    # Check for SAM CLI
    if ! command -v sam >/dev/null 2>&1; then
        missing_prereqs+=("AWS SAM CLI")
    fi

    # If there are missing prerequisites, inform the user and exit
    if [ ${#missing_prereqs[@]} -ne 0 ]; then
        error "The following prerequisites are missing:
${missing_prereqs[*]}

Please install the missing prerequisites. Here are some installation guides:
- AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
- AWS SAM CLI: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html

For AWS credentials, run 'aws configure' to set them up."
    fi
}

check_aws_region() {
    # First try aws configure
    local region
    region=$(aws configure get region 2>/dev/null)
    
    # If not found, check environment variables
    if [ -z "$region" ]; then
        region=${AWS_REGION:-${AWS_DEFAULT_REGION:-""}}
    fi
    
    # If still no region, error out
    if [ -z "$region" ]; then
        error "No AWS region configured. Please set it using 'aws configure' or AWS_REGION environment variable"
    fi

    echo "$region"
}

validate_template() {
    local template="$1"
    local region="$2"
    
    # Check if template exists
    if [ ! -f "$template" ]; then
        error "Template file $template not found in current directory"
    fi

    info "Validating SAM template..."
    if ! sam validate --template-file "$template" --region "$region"; then
        error "Template validation failed"
    fi
}

# Function to print usage
print_usage() {
    echo "Usage: $0 [COMMAND]"
    echo "Commands:"
    echo "  bootstrap   Deploy the stack (default, uses guided mode for first deployment)"
    echo "  configure   Update stack configuration through guided deployment"
    echo "  cleanup     Remove all resources"
    echo "  help        Display this help message"
}

# Main script execution
main() {
    info "AWS Outposts N+M Resiliency Monitoring - Bootstrap Script"
    info "-----------------------------------------------------"
    info "Recommendation: Run this script in AWS CloudShell for the best experience."
    echo ""

    check_prerequisites
    validate_template "$TEMPLATE_NAME" "$(check_aws_region)"

    case "${1:-bootstrap}" in
        "bootstrap")
            if [ ! -f "samconfig.toml" ]; then
                info "No existing configuration found. Running guided deployment..."
                sam deploy --guided --template-file "$TEMPLATE_NAME"
            else
                info "Using existing configuration..."
                sam deploy --template-file "$TEMPLATE_NAME"
            fi
            ;;
        "configure")
            info "Running guided deployment..."
            sam deploy --guided --template-file "$TEMPLATE_NAME"
            ;;
        "cleanup")
            info "Removing all resources..."
            sam delete
            ;;
        "help")
            print_usage
            exit 0
            ;;
        *)
            error "Invalid command. Use: bootstrap, configure, cleanup, or help"
            ;;
    esac
}

main "$@"
