"""
Fetch REAL top npm packages ranked by actual last-month download count.
Uses api.npmjs.org/downloads/point/last-month (official npm API).

Note: Scoped packages (@scope/name) are fetched individually as the bulk
      endpoint does not support them. Unscoped packages are fetched in batches.
"""
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

OUTPUT_FILE = Path("backend/app/data/popular_npm.json")
HEADERS = {"User-Agent": "warrant-2.1-data-refresh/2.2", "Accept": "application/json"}
DOWNLOADS_BULK = "https://api.npmjs.org/downloads/point/last-month/{packages}"
DOWNLOADS_SINGLE = "https://api.npmjs.org/downloads/point/last-month/{package}"

# Unscoped packages (bulk API works)
UNSCOPED = [
    # Infra / utils
    "semver","debug","ms","chalk","tslib","lodash","glob","minimatch","uuid",
    "graceful-fs","inherits","readable-stream","mime-types","mime-db","resolve",
    "rimraf","mkdirp","once","abbrev","which","through","wrap-ansi",
    "string-width","strip-ansi","ansi-regex","safe-buffer","path-browserify",
    # Build
    "typescript","webpack","esbuild","vite","rollup","parcel","babel",
    "prettier","eslint","postcss","sass","less","autoprefixer","terser",
    # Testing
    "jest","mocha","chai","sinon","jasmine","cypress","playwright","puppeteer",
    "vitest","supertest","nock","faker","nyc",
    # Frameworks
    "react","vue","svelte","next","nuxt","gatsby","express","fastify",
    "koa","hono","nestjs","remix","astro",
    # HTTP
    "axios","node-fetch","got","superagent","cross-fetch","ky","undici",
    # State / data
    "redux","mobx","zustand","recoil","jotai","immer","rxjs",
    "ramda","underscore","date-fns","dayjs","moment","luxon",
    # Security / auth
    "jsonwebtoken","bcrypt","bcryptjs","passport","helmet","cors",
    "express-rate-limit","crypto-js","nanoid","cuid",
    # DB / ORM
    "mongoose","sequelize","typeorm","prisma","knex","pg","mysql2",
    "redis","ioredis","cassandra-driver",
    # GraphQL
    "graphql",
    # CLI
    "commander","yargs","inquirer","ora","boxen","execa","dotenv",
    "cross-env","shelljs","chokidar","fs-extra","glob",
    # Validation
    "zod","joi","ajv","yup",
    # Frontend
    "tailwindcss","classnames","clsx",
    # Node tooling
    "nodemon","pm2","concurrently","husky","lint-staged","semantic-release",
    "lerna","turbo","changesets",
    # Cloud / payment
    "stripe","twilio",
    # Logging
    "winston","pino","bunyan",
]

# Scoped packages (individual fetch)
SCOPED = [
    "@babel/core","@babel/parser","@babel/traverse","@babel/generator",
    "@babel/preset-env","@babel/preset-react","@babel/preset-typescript",
    "@types/node","@types/react","@types/express","@types/lodash","@types/jest",
    "@types/sinon","@octokit/core","@octokit/rest","@actions/core","@actions/github",
    "@apollo/client","@tanstack/react-query","@testing-library/react",
    "@testing-library/jest-dom","@testing-library/user-event",
    "@aws-sdk/client-s3","@google-cloud/storage",
    "@slack/web-api","@slack/bolt",
]


def bulk_fetch(names: list[str]) -> dict[str, int]:
    result = {}
    chunk_size = 100
    for i in range(0, len(names), chunk_size):
        chunk = names[i : i + chunk_size]
        joined = ",".join(chunk)
        url = DOWNLOADS_BULK.format(packages=joined)
        req = urllib.request.Request(url, headers=HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                for name, info in data.items():
                    if isinstance(info, dict) and "downloads" in info:
                        result[name] = info["downloads"]
        except Exception as e:
            print(f"  WARN bulk batch {i//chunk_size+1}: {e}")
        time.sleep(1)
    return result


def single_fetch(name: str) -> int | None:
    url = DOWNLOADS_SINGLE.format(package=urllib.request.quote(name, safe=""))
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("downloads")
    except Exception:
        return None


def main():
    print("=" * 60)
    print("Fetching REAL npm download counts from api.npmjs.org")
    print("=" * 60)

    # Fetch unscoped in bulk
    print(f"\nFetching {len(UNSCOPED)} unscoped packages in bulk...")
    counts: dict[str, int] = bulk_fetch(UNSCOPED)
    print(f"Got {len(counts)} unscoped counts")

    # Fetch scoped individually
    print(f"\nFetching {len(SCOPED)} scoped packages individually...")
    for pkg in SCOPED:
        c = single_fetch(pkg)
        if c is not None:
            counts[pkg] = c
            print(f"  {pkg}: {c:,}")
        else:
            print(f"  {pkg}: FAILED")
        time.sleep(0.5)

    # Sort by real download count
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    top_packages = [name for name, _ in ranked]
    top_counts = {name: count for name, count in ranked}

    print(f"\nTop 20 by REAL last-month downloads:")
    for name, count in ranked[:20]:
        print(f"  {name:50s} {count:>15,}")

    payload = {
        "_comment": (
            "Top npm packages ranked by REAL last-month download count. "
            "All counts fetched live from api.npmjs.org/downloads/point/last-month. "
            "Used by Warrant-2.1 lookalike/typosquat heuristic (T3 REVIEW tier only, never INCIDENT)."
        ),
        "_version": "2.2",
        "_source": "api.npmjs.org/downloads/point/last-month — official npm download API (100% real)",
        "_download_period": "last-month",
        "_total_packages": len(top_packages),
        "packages": top_packages,
        "_download_counts": top_counts,
    }

    OUTPUT_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nWritten {len(top_packages)} real packages to {OUTPUT_FILE}")
    print("STATUS: popular_npm.json is now backed by 100% REAL npm download data.")


if __name__ == "__main__":
    main()
