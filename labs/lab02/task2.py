import argparse
import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Використовуємо локальний логер 
logger = logging.getLogger(__name__)


@dataclass
class AuthEvent:
    timestamp: datetime
    ip: str
    user: str
    status: str


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )


def parse_auth_log(
    log_path: Path, threshold: int, window_min: int, output_json: Path | None
):
    if not log_path.exists():
        logger.error(f"Файл журналу не знайдено: {log_path}")
        return

    logger.info(f"Analyzing authentication events in {log_path}...")

    log_pattern = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+.*?"
        r"(?P<status>Failed|Accepted)\s+password\s+for\s+(invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    )

    ip_events = defaultdict(list)
    target_users = defaultdict(set)

    processed_lines = 0
    start_time = None
    end_time = None

    current_year = datetime.now(timezone.utc).year

    try:
        with log_path.open("r", encoding="utf-8") as file:
            for line in file:
                processed_lines += 1
                match = log_pattern.search(line)

                if match:
                    data = match.groupdict()
                    time_str = f"{current_year} {data['month']} {int(data['day']):02d} {data['time']}"

                    try:
                        timestamp = datetime.strptime(
                            time_str, "%Y %b %d %H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue

                    if start_time is None or timestamp < start_time:
                        start_time = timestamp
                    if end_time is None or timestamp > end_time:
                        end_time = timestamp

                    ip = data["ip"]
                    user = data["user"]
                    status = data["status"]

                    event = AuthEvent(
                        timestamp=timestamp, ip=ip, user=user, status=status
                    )
                    ip_events[ip].append(event)
                    target_users[ip].add(user)

    except PermissionError:
        logger.error(f"Немає прав на читання файлу: {log_path}")
        return

    if start_time and end_time:
        logger.info(
            f"Processed {processed_lines} lines (Time range: {start_time} - {end_time})"
        )
    else:
        logger.info(f"Processed {processed_lines} lines.")

    logger.info("=== SSH Bruteforce Detection Results ===")
    logger.info(
        f"Failed Attempts Threshold: >{threshold} attempts in {window_min} minutes"
    )

    window_delta = timedelta(minutes=window_min)
    blocklist = []

    for ip, events in ip_events.items():
        events.sort(key=lambda e: e.timestamp)
        failed_timestamps = [e.timestamp for e in events if e.status == "Failed"]
        accepted_timestamps = [e.timestamp for e in events if e.status == "Accepted"]

        max_in_window = 0

        for i in range(len(failed_timestamps)):
            count = 1
            for j in range(i + 1, len(failed_timestamps)):
                if failed_timestamps[j] - failed_timestamps[i] <= window_delta:
                    count += 1
                else:
                    break
            max_in_window = max(max_in_window, count)

        if max_in_window >= threshold:
            users_str = ", ".join(list(target_users[ip])[:5])
            if len(target_users[ip]) > 5:
                users_str += "..."

            logger.error(
                f"Bruteforce Detected! IP: {ip} | Max Failures in window: {max_in_window} | Total Failures: {len(failed_timestamps)} | Target Users: {users_str}"
            )
            blocklist.append(ip)

            if failed_timestamps:
                first_fail = failed_timestamps[0]
                successful_breaches = [t for t in accepted_timestamps if t > first_fail]
                if successful_breaches:
                    logger.critical(
                        f"COMPROMISE ALERT! Hacker from IP {ip} SUCCESSFULLY logged in after bruteforce attempts at {successful_breaches[-1]}!"
                    )

    if blocklist:
        logger.info("=== Recommended Blocklist (IPs) ===")
        for ip in blocklist:
            logger.info(f" - {ip}")

        if output_json:
            try:
                output_json.parent.mkdir(parents=True, exist_ok=True)
                with output_json.open("w", encoding="utf-8") as f:
                    json.dump({"blocked_ips": blocklist}, f, indent=4)
                logger.info(f"Exported blocklist to {output_json}")
            except OSError as e:
                logger.error(f"Не вдалося зберегти звіт: {e}")
    else:
        logger.info("Брутфорс атак не виявлено за заданими критеріями.")


def main():
    parser = argparse.ArgumentParser(description="SSH Auth Log Bruteforce Detector")
    parser.add_argument(
        "--auth-log", type=Path, required=True, help="Шлях до файлу auth.log"
    )
    parser.add_argument(
        "--threshold", type=int, default=5, help="Поріг спроб (дефолт: 5)"
    )
    parser.add_argument(
        "--window-min", type=int, default=5, help="Часове вікно у хвилинах"
    )
    parser.add_argument("--output-json", type=Path, help="Шлях до файлу звіту JSON")
    args = parser.parse_args()

    setup_logging()

    parse_auth_log(
        log_path=args.auth_log,
        threshold=args.threshold,
        window_min=args.window_min,
        output_json=args.output_json,
    )


if __name__ == "__main__":
    main()
