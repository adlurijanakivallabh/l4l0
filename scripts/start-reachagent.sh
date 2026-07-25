#!/bin/bash
# ReachAgent environment startup — run this whenever you sit down to work.
# No `set -e`: a failed `docker compose up` must NOT skip the status report
# below — that report is the whole point of the script. Failures surface as
# DOWN / non-200 lines, not a silent early exit.
set -uo pipefail

REACHAGENT_DIR="$HOME/Downloads/reachagent"
CRAPI_COMPOSE="$HOME/Downloads/crAPI-main/deploy/docker/docker-compose.yml"

echo "==> Starting Neo4j..."
docker start neo4j 2>/dev/null || echo "  (already running, or 'neo4j' container not found — check manually)"

echo "==> Waiting for Neo4j bolt (7687) to accept connections..."
neo4j_up=false
for i in $(seq 1 15); do
  if (echo > /dev/tcp/127.0.0.1/7687) 2>/dev/null; then
    neo4j_up=true
    break
  fi
  sleep 2
done

echo "==> Starting crAPI (pinned reachagent-crapi project)..."
cd "$REACHAGENT_DIR" || { echo "  ✗ cannot cd into $REACHAGENT_DIR"; exit 1; }
CRAPI_COMPOSE_PATH="$CRAPI_COMPOSE" \
  docker compose -f docker-compose.crapi.yml up -d \
  || echo "  ✗ crAPI compose failed — see status below / 'docker compose -f docker-compose.crapi.yml logs'"

echo "==> Starting VAmPI (both toggles)..."
docker compose up -d \
  || echo "  ✗ VAmPI compose failed — see status below / 'docker compose logs'"

echo "==> Waiting for services to settle..."
sleep 5

echo ""
echo "==> Status check:"

echo -n "-- Neo4j bolt (7687): "
if $neo4j_up; then echo "UP"; else echo "DOWN — check: docker logs neo4j"; fi

echo -n "-- crAPI web (8888): "
crapi_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8888 || echo "000")
echo "HTTP $crapi_code"

echo -n "-- VAmPI vulnerable (5000): "
vamp_vuln=$(curl -s http://localhost:5000/ | grep -o '"vulnerable":[01]' || echo "DOWN")
echo "$vamp_vuln"

echo -n "-- VAmPI secure (5002): "
vamp_secure=$(curl -s http://localhost:5002/ | grep -o '"vulnerable":[01]' || echo "DOWN")
echo "$vamp_secure"

echo ""
if $neo4j_up \
  && [[ "$crapi_code" == "200" ]] \
  && [[ "$vamp_vuln" == '"vulnerable":1' ]] \
  && [[ "$vamp_secure" == '"vulnerable":0' ]]; then
  echo "✅ All services up and correctly toggled. Ready to work."
else
  echo "⚠️  Something isn't right — check the lines above before starting Claude Code."
fi

echo ""
echo "==> cd into the project:"
echo "    cd $REACHAGENT_DIR"
