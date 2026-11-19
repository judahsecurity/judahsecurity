---
name: ml_pipeline_rbac
description: Planner scenario for ML train / celery-task endpoints missing role checks.
triggers: (?i)/api/v1/train/?|/api/v1/celery-task/?|logixtwin-train|/api/drf-celery|/api/v1/optimize/?
---

Validation bar: ML train/delete missing RBAC IMPROVE until a self-reg/low-priv session can train or queue celery; do not delete production models.
