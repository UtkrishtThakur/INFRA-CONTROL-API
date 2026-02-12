from utils import normalize_path

@traffic_router.post(
    "/traffic",
    dependencies=[Depends(verify_worker_secret)],
)
def ingest_traffic(payload: TrafficLogIngest, db: Session = Depends(get_db)):
    """
    Canonical traffic ingestion endpoint.

    Guarantees:
    - Control API is the authority for endpoint identity
    - No normalization inconsistency
    - No endpoint fragmentation
    - Stable historical aggregation
    """

    try:
        now = datetime.utcnow()

        # --------------------------------------------------
        # 1. Canonical Normalization (CONTROL IS AUTHORITY)
        # --------------------------------------------------
        normalized_endpoint = normalize_path(payload.path)

        # Optional: detect worker mismatch (debug only)
        if payload.endpoint and payload.endpoint != normalized_endpoint:
            logger.warning(
                f"Worker endpoint mismatch. "
                f"Worker: {payload.endpoint}, "
                f"Control: {normalized_endpoint}"
            )

        # --------------------------------------------------
        # 2. Resolve API Key ID (optional)
        # --------------------------------------------------
        api_key_id = None
        if payload.api_key_hash:
            key = (
                db.query(APIKey)
                .filter(APIKey.key_hash == payload.api_key_hash)
                .first()
            )
            if key:
                api_key_id = key.id

        # --------------------------------------------------
        # 3. Endpoint Registry (Upsert by Canonical Pattern)
        # --------------------------------------------------
        endpoint = (
            db.query(Endpoint)
            .filter(
                Endpoint.project_id == payload.project_id,
                Endpoint.method == payload.method,
                Endpoint.pattern == normalized_endpoint,
            )
            .first()
        )

        if not endpoint:
            endpoint = Endpoint(
                project_id=payload.project_id,
                method=payload.method,
                pattern=normalized_endpoint,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(endpoint)
            db.flush()  # ensures endpoint.id is available
        else:
            endpoint.last_seen_at = now

        # --------------------------------------------------
        # 4. Hourly Metric Bucket (Canonical Endpoint Only)
        # --------------------------------------------------
        bucket_start = now.replace(minute=0, second=0, microsecond=0)

        bucket = (
            db.query(MetricBucket)
            .filter(
                MetricBucket.endpoint_id == endpoint.id,
                MetricBucket.bucket_start == bucket_start,
            )
            .first()
        )

        if not bucket:
            bucket = MetricBucket(
                endpoint_id=endpoint.id,
                bucket_start=bucket_start,
                request_count=0,
                error_count=0,
                latency_sum=0,
                risk_score_sum=0,
                throttled_count=0,
                blocked_count=0,
            )
            db.add(bucket)

        bucket.request_count += 1
        bucket.latency_sum += payload.latency_ms

        if payload.status_code >= 400:
            bucket.error_count += 1

        if payload.risk_score is not None:
            bucket.risk_score_sum += int(payload.risk_score * 100)

        if payload.decision == "THROTTLE":
            bucket.throttled_count += 1
        elif payload.decision == "BLOCK":
            bucket.blocked_count += 1

        # --------------------------------------------------
        # 5. Raw Traffic Log (Full Fidelity)
        # --------------------------------------------------
        log_timestamp = payload.timestamp or now

        log = TrafficLog(
            project_id=payload.project_id,
            api_key_id=api_key_id,
            timestamp=log_timestamp,
            ip=payload.ip,
            user_agent=payload.user_agent,
            path=payload.path,  # raw
            endpoint=normalized_endpoint,  # canonical
            method=payload.method,
            status_code=payload.status_code,
            decision=payload.decision,
            risk_score=(
                int(payload.risk_score * 100)
                if payload.risk_score is not None
                else None
            ),
            latency_ms=payload.latency_ms,
        )

        db.add(log)
        db.commit()

        return {"status": "ingested"}

    except Exception as e:
        db.rollback()
        logger.error(f"Traffic ingestion failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Ingestion failed")
