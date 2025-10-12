#!/usr/bin/env bash
# test_git_clone_simple.sh - Simple test with a small, guaranteed-to-exist repository
# This tests the non-interactive git functionality with a minimal repository

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

# Test with a small, guaranteed public repository
echo "Testing non-interactive git clone functionality..."
echo "Using a small test repository to verify the approach works..."
echo ""

# Clean up any previous test
rm -rf /tmp/test_simple_clone 2>/dev/null || true

# Test with a very small repository that definitely exists
TEST_REPO="https://github.com/octocat/Hello-World.git"
echo "🧪 Testing with: $TEST_REPO"

# Test the function
if git_clone_noninteractive "$TEST_REPO" "/tmp/test_simple_clone" 1; then
    echo ""
    echo "🎉 Basic test successful! Non-interactive git clone working properly."
    
    if [ -d "/tmp/test_simple_clone/.git" ]; then
        echo "   Repository verification: ✅ .git directory found"
        echo "   Repository size: $(du -sh /tmp/test_simple_clone 2>/dev/null | cut -f1 || echo 'unknown')"
        echo "   Files cloned: $(find /tmp/test_simple_clone -type f 2>/dev/null | wc -l || echo '0')"
        
        # Show a sample file to prove it worked
        if [ -f "/tmp/test_simple_clone/README" ]; then
            echo "   Sample content found: README file exists"
        fi
    else
        echo "   ❌ Repository verification failed: no .git directory"
        exit 1
    fi
else
    echo ""
    echo "❌ Basic test failed! Git clone did not complete successfully."
    exit 1
fi

# Clean up
rm -rf /tmp/test_simple_clone 2>/dev/null || true

echo ""
echo "✅ Test completed successfully!"
echo ""
echo "Now testing with the actual Kubernetes Goat repository..."

# Test with the actual Kubernetes Goat repository
KUBERNETES_GOAT_REPO="https://github.com/madhuakula/kubernetes-goat.git"
echo "🔍 Testing Kubernetes Goat repository: $KUBERNETES_GOAT_REPO"

# Clean up
rm -rf /tmp/test_kgoat_clone 2>/dev/null || true

if git_clone_noninteractive "$KUBERNETES_GOAT_REPO" "/tmp/test_kgoat_clone" 1; then
    echo ""
    echo "🎉 Kubernetes Goat repository test successful!"
    
    if [ -d "/tmp/test_kgoat_clone/.git" ]; then
        echo "   Repository verification: ✅ .git directory found"
        echo "   Repository size: $(du -sh /tmp/test_kgoat_clone 2>/dev/null | cut -f1 || echo 'unknown')"
        echo "   Files cloned: $(find /tmp/test_kgoat_clone -type f 2>/dev/null | wc -l || echo '0')"
        
        # Look for typical Kubernetes Goat files
        if [ -f "/tmp/test_kgoat_clone/README.md" ]; then
            echo "   Kubernetes Goat files found: ✅ README.md exists"
        fi
        
        # Check for manifest directories
        for dir in "guide" "platforms" "scenarios"; do
            if [ -d "/tmp/test_kgoat_clone/$dir" ]; then
                echo "   Found directory: $dir"
            fi
        done
    else
        echo "   ❌ Repository verification failed: no .git directory"
    fi
else
    echo ""
    echo "❌ Kubernetes Goat repository test failed!"
    echo "This might be due to:"
    echo "   - Network connectivity issues"
    echo "   - Repository URL changes"
    echo "   - Authentication requirements"
    echo ""
    echo "The basic git clone functionality works, but this specific repository"
    echo "may need to be checked manually or replaced with an alternative."
fi

# Clean up
rm -rf /tmp/test_kgoat_clone 2>/dev/null || true

echo ""
echo "This same non-interactive approach is used in the main setup.sh script"
echo "to ensure git operations never prompt for user input."
