#!/usr/bin/env bash
# test_git_clone.sh - Demonstration of non-interactive git clone
# This script shows how the enhanced setup.sh handles git operations without user prompts

set -euo pipefail

# Test the git_clone_noninteractive function
git_clone_noninteractive() {
    local repo_url="$1"
    local target_dir="$2"
    local depth="${3:-1}"
    
    echo "🔗 Cloning repository: $repo_url"
    
    # Configure git for non-interactive use
    export GIT_TERMINAL_PROMPT=0
    export GIT_ASKPASS=/bin/true
    export SSH_ASKPASS=/bin/true
    
    # Use HTTPS and disable prompts
    local clone_url="$repo_url"
    if [[ "$clone_url" =~ ^git@ ]]; then
        # Convert SSH to HTTPS
        clone_url=$(echo "$clone_url" | sed 's|git@github.com:|https://github.com/|')
        echo "   Converted SSH URL to HTTPS: $clone_url"
    fi
    
    # Ensure directory exists
    mkdir -p "$(dirname "$target_dir")"
    
    # Clone with specific options to avoid prompts
    echo "   Executing git clone with non-interactive settings..."
    git -c advice.detachedHead=false \
        -c init.defaultBranch=main \
        -c user.name="KubeLab Setup" \
        -c user.email="setup@kubelab.local" \
        clone --depth "$depth" --quiet --no-progress \
        "$clone_url" "$target_dir"
    
    echo "✅ Repository cloned successfully to: $target_dir"
}

# Test with a small public repository
echo "Testing non-interactive git clone functionality..."
echo "This demonstrates how the setup script avoids user prompts during git operations."
echo ""

# Clean up any previous test
rm -rf /tmp/test_clone 2>/dev/null || true

# Test the function
git_clone_noninteractive "https://github.com/kubernetes/goat.git" "/tmp/test_clone" 1

# Verify the clone worked
if [ -d "/tmp/test_clone/.git" ]; then
    echo ""
    echo "🎉 Test successful! Non-interactive git clone working properly."
    echo "   Repository size: $(du -sh /tmp/test_clone | cut -f1)"
    echo "   Files cloned: $(find /tmp/test_clone -type f | wc -l)"
else
    echo ""
    echo "❌ Test failed! Repository was not cloned properly."
    exit 1
fi

# Clean up
rm -rf /tmp/test_clone

echo ""
echo "This same approach is used in the main setup.sh script to ensure"
echo "git operations never prompt for user input, even with SSH URLs."
