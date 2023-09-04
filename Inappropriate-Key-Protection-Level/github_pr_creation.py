import os
import shutil
import git
from github import Github

def main():
    # Constants
    REPO_URL = "https://github.com/benton0188/GCP-Privacy.git"
    LOCAL_REPO_PATH = "/home/admin_/temps"
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    FILE_PATH = "/home/admin_/cloudsql_update.tf"
    DEST_PATH = f"{LOCAL_REPO_PATH}/cloudsql.tf"
    BRANCH_NAME = "staging"

    # Clone the repo
    repo = git.Repo.clone_from(REPO_URL, LOCAL_REPO_PATH)

    # Checkout a new branch
    repo.git.checkout("-b", BRANCH_NAME)

    # Copy file from local directory to the cloned repo
    shutil.copy(FILE_PATH, DEST_PATH)

    # Add the changes to git and commit
    repo.git.add("--all")
    repo.git.commit("-m", "Added file")

    # Fetch the latest changes from the remote repository
    repo.git.fetch("origin", BRANCH_NAME)

    # Merge or rebase the latest changes from the remote staging branch
    try:
        repo.git.merge(f"origin/{BRANCH_NAME}")
    except git.exc.GitCommandError as e:
        print("Merge failed:", e)

    # Push the changes to remote
    try:
        repo.git.push("--set-upstream", "origin", BRANCH_NAME)
    except git.exc.GitCommandError as e:
        print("Push failed:", e)

    # Create a PR
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo("benton0188/GCP-Privacy")
        pr = repo.create_pull(
            title="Automated PR from Warden",
            body="This is an automated PR.",
            base="main",
            head=BRANCH_NAME,
        )
        print(f"Successfully created PR: {pr.html_url}")
    except Exception as e:
        print(f"Failed to create PR: {e}")

if __name__ == "__main__":
    main()
