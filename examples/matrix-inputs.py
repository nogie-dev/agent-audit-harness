"""Compose the offline matrix fixture's fixed recipe and source-bound case specification."""

import json
import sys
from pathlib import Path

from agent_audit_harness.pipeline import digest, save_json

root = Path(sys.argv[1])
image = sys.argv[2]
recipe = json.loads((root / "approved/recipe.json").read_text())
receipt = json.loads((root / "approved/review.json").read_text())
replacement = json.loads((Path(__file__).parent / "matrix-fix.json").read_text())
fixed = {**recipe, "replacements": [replacement]}
save_json(root / "fixed-recipe.json", fixed)
save_json(
    root / "matrix-spec.json",
    {
        "schema_version": 1,
        "poc_review": "approved",
        "poc_review_sha256": receipt["identity_sha256"],
        "recipe_sha256": digest(recipe),
        "fixed_recipe": "fixed-recipe.json",
        "fixed_recipe_sha256": digest(fixed),
        "cases": [{"id": case["id"], "image": image} for case in recipe["configurations"]],
    },
)
