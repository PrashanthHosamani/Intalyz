"""
adapters/github_adapter.py
Technical Infrastructure — GitHub repository & organisation discovery.
Searches for public repos, org members, and potential exposed secrets.
"""

import logging
import re
from typing import List

from core.base_adapter import BaseAdapter, AdapterResult
from config import settings

logger = logging.getLogger(__name__)

# Patterns that suggest secrets were accidentally committed
SECRET_PATTERNS = [
    r"api[_\-]?key",
    r"secret[_\-]?key",
    r"password",
    r"token",
    r"aws[_\-]access",
    r"private[_\-]key",
]


class GitHubAdapter(BaseAdapter):
    """
    Uses the GitHub REST API (via PyGithub) to find:
    - Organisations matching the entity name
    - Public repositories
    - README/commit patterns suggesting leaked secrets
    """

    CATEGORY     = "infrastructure"
    ADAPTER_NAME = "github"

    def fetch(self, entity: str, entity_type: str) -> AdapterResult:
        findings = []
        errors   = []

        if not settings.GITHUB_TOKEN:
            return AdapterResult(
                self.ADAPTER_NAME, self.CATEGORY, [],
                errors=["GITHUB_TOKEN not set in .env"]
            )

        try:
            from github import Github, GithubException
            gh = Github(settings.GITHUB_TOKEN)

            import concurrent.futures

            # ── Search repositories ────────────────────────────────────────
            repos = gh.search_repositories(query=f"{entity} in:name,description", sort="stars")
            repo_list = []
            for repo in repos:
                repo_list.append(repo)
                if len(repo_list) >= settings.GITHUB_MAX_REPOS:
                    break
            
            def process_repo(repo):
                risk_tags = ["public_repo"]
                readme_content = self._get_readme(repo)
                if readme_content and self._has_secrets(readme_content):
                    risk_tags.append("leaked_secret")

                return self.make_finding(
                    title="GitHub Repository",
                    value={
                        "name":        repo.full_name,
                        "url":         repo.html_url,
                        "description": repo.description,
                        "stars":       repo.stargazers_count,
                        "language":    repo.language,
                        "created":     str(repo.created_at),
                        "updated":     str(repo.updated_at),
                        "topics":      repo.get_topics(),
                        "is_fork":     repo.fork,
                    },
                    source_url=repo.html_url,
                    risk_tags=risk_tags,
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                findings.extend(executor.map(process_repo, repo_list))

            # ── Search organisations ───────────────────────────────────────
            orgs = gh.search_users(query=f"{entity} type:org")
            org_list = []
            for org in orgs:
                org_list.append(org)
                if len(org_list) >= settings.GITHUB_MAX_ORGS:
                    break

            def process_org(org):
                return self.make_finding(
                    title="GitHub Organisation",
                    value={
                        "login":    org.login,
                        "url":      org.html_url,
                        "name":     org.name,
                        "bio":      org.bio,
                        "location": org.location,
                        "email":    org.email,
                        "public_repos": org.public_repos,
                    },
                    source_url=org.html_url,
                    risk_tags=["public_repo"],
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                findings.extend(executor.map(process_org, org_list))

        except Exception as exc:
            msg = f"GitHub API error: {exc}"
            logger.error(msg)
            errors.append(msg)

        return AdapterResult(self.ADAPTER_NAME, self.CATEGORY, findings, errors)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_readme(repo) -> str:
        try:
            return repo.get_readme().decoded_content.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @staticmethod
    def _has_secrets(text: str) -> bool:
        lowered = text.lower()
        for pattern in SECRET_PATTERNS:
            if re.search(pattern, lowered):
                return True
        return False
