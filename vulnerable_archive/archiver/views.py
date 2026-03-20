import datetime
import ipaddress
import os
import re
import socket
from datetime import timezone
from urllib.parse import urlparse

import jwt
import requests
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .llm_utils import query_llm
from .models import Archive


# --- Security Helpers ---


def _is_url_safe(url):
    """Validate that a URL is safe to fetch (no internal/private IPs, only http/https)."""
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
            return False

        # Resolve hostname and check if IP is private/reserved
        try:
            resolved_ip = socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )[0][4][0]
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
            ):
                return False
        except (socket.gaierror, ValueError):
            return False

        return True
    except Exception:
        return False


def _strip_hidden_html(html_content):
    """Remove hidden elements that could contain prompt injection payloads."""
    cleaned = re.sub(
        r"<[^>]*style\s*=\s*\"[^\"]*display\s*:\s*none[^\"]*\"[^>]*>.*?</[^>]+>",
        "",
        html_content,
        flags=re.DOTALL | re.IGNORECASE,
    )
    cleaned = re.sub(
        r"<[^>]*style\s*=\s*\"[^\"]*visibility\s*:\s*hidden[^\"]*\"[^>]*>.*?</[^>]+>",
        "",
        cleaned,
        flags=re.DOTALL | re.IGNORECASE,
    )
    cleaned = re.sub(r"<!--.*?-->", "", cleaned, flags=re.DOTALL)
    return cleaned


# --- Views ---


def register(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Registration successful!")
            return redirect("dashboard")
    else:
        form = UserCreationForm()
    return render(request, "archiver/register.html", {"form": form})


@login_required
def dashboard(request):
    return render(request, "archiver/dashboard.html")


@login_required
def generate_token(request):
    # FIX #1: JWT secret loaded from environment variable
    SECRET = os.environ.get("JWT_SECRET", "fallback-dev-secret-change-in-production")

    payload = {
        "user_id": request.user.id,
        "username": request.user.username,
        "exp": datetime.datetime.now(timezone.utc) + datetime.timedelta(days=1),
    }

    token = jwt.encode(payload, SECRET, algorithm="HS256")

    return JsonResponse({"token": token, "note": "Token generated successfully."})


@login_required
def archive_list(request):
    archives = Archive.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "archiver/archive_list.html", {"archives": archives})


@login_required
def add_archive(request):
    if request.method == "POST":
        url = request.POST.get("url")
        notes = request.POST.get("notes")

        if url:
            # FIX #11: SSRF protection - validate URL before fetching
            if not _is_url_safe(url):
                messages.error(
                    request,
                    "Invalid or blocked URL. Only public HTTP/HTTPS URLs are allowed.",
                )
                return render(request, "archiver/add_archive.html")

            try:
                response = requests.get(url, timeout=10)
                title = "No Title Found"
                if "<title>" in response.text:
                    try:
                        title = (
                            response.text.split("<title>", 1)[1]
                            .split("</title>", 1)[0]
                            .strip()
                        )
                    except IndexError:
                        pass

                Archive.objects.create(
                    user=request.user,
                    url=url,
                    title=title,
                    content=response.text,
                    notes=notes,
                )
                messages.success(request, "URL archived successfully!")
                return redirect("archive_list")
            except Exception as e:
                messages.error(request, f"Failed to archive URL: {str(e)}")

    return render(request, "archiver/add_archive.html")


@login_required
def view_archive(request, archive_id):
    # FIX #5: IDOR - enforce ownership check
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    return render(request, "archiver/view_archive.html", {"archive": archive})


@login_required
def edit_archive(request, archive_id):
    # FIX #5: IDOR - enforce ownership check
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.notes = request.POST.get("notes")
        archive.save()
        messages.success(request, "Archive updated successfully!")
        return redirect("archive_list")

    return render(request, "archiver/edit_archive.html", {"archive": archive})


@login_required
def delete_archive(request, archive_id):
    # FIX #5: IDOR - enforce ownership check
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)

    if request.method == "POST":
        archive.delete()
        messages.success(request, "Archive deleted successfully!")
        return redirect("archive_list")

    return render(request, "archiver/delete_archive.html", {"archive": archive})


@login_required
def search_archives(request):
    query = request.GET.get("q", "")
    results = []

    if query:
        try:
            # FIX #4: Use Django ORM instead of raw SQL to prevent SQL injection
            archives = Archive.objects.filter(
                user=request.user, title__icontains=query
            ).select_related("user")

            results = [
                {
                    "id": a.id,
                    "title": a.title,
                    "url": a.url,
                    "created_at": a.created_at,
                    "username": a.user.username,
                }
                for a in archives
            ]
        except Exception:
            # FIX #12: Generic error message - no SQL details leaked
            messages.error(
                request, "An error occurred while searching. Please try again."
            )

    return render(request, "archiver/search.html", {"results": results, "query": query})


@login_required
def ask_database(request):
    answer = None
    sql_query = None
    user_input = request.POST.get("prompt", "")

    if request.method == "POST" and user_input:
        schema_info = """
        Table: archiver_archive
        Columns: id, title, url, content, notes, created_at, user_id
        """

        system_prompt = f"""
        You are a SQL expert. Convert the user's natural language query into a raw SQLite SQL query.
        The table name is 'archiver_archive'.
        Do not explain. Return ONLY the SQL query.
        IMPORTANT: Always filter by user_id = {request.user.id}. Only generate SELECT queries.
        Current User ID: {request.user.id}
        Schema:
        {schema_info}
        """

        sql_query = query_llm(user_input, system_instruction=system_prompt).strip()

        # Clean up markdown code blocks if present
        if "```sql" in sql_query:
            sql_query = sql_query.split("```sql")[1].split("```")[0].strip()
        elif "```" in sql_query:
            sql_query = sql_query.split("```")[1].strip()

        # FIX #8: Sanitize LLM-generated SQL before execution
        # Strip comments (-- and /* */) to prevent filter bypass
        sanitized = re.sub(r"--.*$", "", sql_query, flags=re.MULTILINE)
        sanitized = re.sub(r"/\*.*?\*/", "", sanitized, flags=re.DOTALL)
        normalized = sanitized.strip().rstrip(";").strip()

        # Only allow SELECT statements (blocks DELETE, DROP, UPDATE, INSERT)
        if not normalized.upper().startswith("SELECT"):
            answer = "Only SELECT queries are allowed."
        # Only allow queries against archiver_archive (blocks JOIN to auth_user etc.)
        elif any(
            table in normalized.upper()
            for table in ["AUTH_USER", "DJANGO_SESSION", "SQLITE_MASTER"]
        ):
            answer = "Access restricted to archive data only."
        else:
            # Force user_id filter to prevent cross-user data access
            if " WHERE " in normalized.upper():
                enforced_query = (
                    normalized + f" AND user_id = {int(request.user.id)}"
                )
            else:
                enforced_query = (
                    normalized + f" WHERE user_id = {int(request.user.id)}"
                )

            try:
                with connection.cursor() as cursor:
                    cursor.execute(enforced_query)
                    if cursor.description:
                        columns = [col[0] for col in cursor.description]
                        results = [
                            dict(zip(columns, row)) for row in cursor.fetchall()
                        ]
                        answer = results
                    else:
                        answer = "Query executed successfully (no results returned)."
            except Exception:
                answer = "An error occurred while running the query."

    return render(
        request,
        "archiver/ask_database.html",
        {"answer": answer, "sql_query": sql_query, "prompt": user_input},
    )


@login_required
def export_summary(request):
    if request.method == "POST":
        topic = request.POST.get("topic")
        filename_hint = request.POST.get("filename_hint")

        # Prompt for LLM to generate summary content
        content_prompt = f"Write a short summary about: {topic}"
        summary_content = query_llm(content_prompt)

        # FIX #7: Build path deterministically - don't let LLM control file path
        safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename_hint or "summary")
        if not safe_filename.endswith(".txt"):
            safe_filename += ".txt"

        base_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "exported_summaries"
        )
        base_dir = os.path.realpath(base_dir)
        file_path = os.path.join(base_dir, safe_filename)
        file_path = os.path.realpath(file_path)

        # Verify the resolved path is still within the base directory
        if not file_path.startswith(base_dir):
            messages.error(request, "Invalid filename.")
            return render(request, "archiver/export_summary.html")

        try:
            os.makedirs(base_dir, exist_ok=True)
            with open(file_path, "w") as f:
                f.write(summary_content)

            messages.success(request, f"Summary written to: {safe_filename}")
        except Exception:
            messages.error(
                request, "An error occurred while exporting the summary."
            )

    return render(request, "archiver/export_summary.html")


@login_required
def enrich_archive(request, archive_id):
    # FIX #5: IDOR - enforce ownership check on enrich too
    archive = get_object_or_404(Archive, pk=archive_id, user=request.user)
    llm_response = None

    if request.method == "POST":
        user_instruction = request.POST.get(
            "instruction", "Summarize this content and find related links."
        )

        system_prompt = """
        You are an AI assistant that enriches archived content.
        You can fetch external data if explicitly requested or if the content implies it.
        Only use public URLs. Never fetch internal or private network URLs.
        """

        # FIX #6: Strip hidden HTML to reduce prompt injection surface
        cleaned_content = _strip_hidden_html(archive.content)

        # FIX #6: Don't pass user notes to LLM (prevents note-based data exfiltration)
        prompt = f"""
        User Instruction: {user_instruction}

        Archive Content:
        {cleaned_content}
        """

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "fetch_url",
                    "description": "Fetch data from a URL",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "The URL to fetch",
                            }
                        },
                        "required": ["url"],
                    },
                },
            }
        ]

        message = query_llm(prompt, system_instruction=system_prompt, tools=tools)

        if message.get("tool_calls"):
            tool_calls = message["tool_calls"]
            llm_response = f"LLM decided to use tools:\n{tool_calls}\n\n"

            # FIX #6: Only allow URLs matching the archive's original domain
            archive_domain = urlparse(archive.url).hostname
            user_domains = set()
            for word in user_instruction.split():
                try:
                    parsed = urlparse(word)
                    if parsed.hostname:
                        user_domains.add(parsed.hostname)
                except Exception:
                    pass
            allowed_domains = {archive_domain} | user_domains

            for tool in tool_calls:
                if tool["function"]["name"] == "fetch_url":
                    url_to_fetch = tool["function"]["arguments"]["url"]
                    fetch_domain = urlparse(url_to_fetch).hostname

                    if fetch_domain not in allowed_domains:
                        llm_response += (
                            f"Blocked URL (domain not in allowlist): {url_to_fetch}\n"
                        )
                        continue

                    if not _is_url_safe(url_to_fetch):
                        llm_response += f"Blocked unsafe URL: {url_to_fetch}\n"
                        continue

                    try:
                        requests.get(url_to_fetch, timeout=5)
                        llm_response += f"Successfully fetched: {url_to_fetch}\n"
                    except Exception as e:
                        llm_response += (
                            f"Failed to fetch {url_to_fetch}: {str(e)}\n"
                        )
        else:
            llm_response = message.get("content", "")

    return render(
        request,
        "archiver/enrich_archive.html",
        {"archive": archive, "llm_response": llm_response},
    )
