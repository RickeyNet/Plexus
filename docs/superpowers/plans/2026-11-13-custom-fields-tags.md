# Custom Fields and Tags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admin-defined custom fields and tags on hosts, inventory groups and IPAM prefixes: recorded, shown, filterable, exported.

**Architecture:** Four generic tables keyed by `(object_type, object_key)`, one storage module, one pure validation module, one routes module holding four routers that are registered with the access rules of the features they sit beside. Existing list endpoints return the data inline; the React pages use four shared components.

**Tech Stack:** FastAPI, asyncpg through the `routes.database` facade (`?` placeholders), Postgres; React, TanStack Query, Vitest.

**Spec:** `docs/superpowers/specs/2026-11-13-custom-fields-tags-design.md`

## Global Constraints

- **No commits.** Nobody runs `git commit` or `git push`. Each task ends with its verification step; the user commits.
- **No formatter over directories.** Never `ruff format` or `ruff check --fix` a directory; name the files you created or changed. The tree holds the user's uncommitted work.
- **Reuse before writing.** Grep `netcontrol/`, `routes/`, `templates/` and the frontend `src/` for an existing helper before adding one. Known reusable pieces: `tests/mcp_helpers.py` (`CsrfClient`, `admin_client`, `user_client`, `create_user`), `netcontrol/routes/shared.py` (`_audit`, `_corr_id`, `_session_user`, `_get_session`), `routes.database` (`_is_unique_violation`, `row_to_dict`, `rows_to_list`), frontend `components/` (`Modal`, `ModalActions`, `FieldError`, `Callout`, `ConfirmDialog`, `DataTable`, `Menu`, `DeleteButton`, `EmptyState`), `lib/themeColors.ts`, `api/client.ts` (`apiRequest`), `pages/Settings/FormFields.tsx`.
- **No real environment data.** Tests, docs and samples use invented names, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `example.com`.
- **Object types:** exactly `host`, `group`, `prefix`.
- **Field types:** exactly `text`, `number`, `boolean`, `date`, `url`, `select`.
- **Tag colors:** exactly `gray`, `red`, `orange`, `yellow`, `green`, `teal`, `blue`, `purple`; default `gray`.
- **Field key:** `^[a-z][a-z0-9_]{0,49}$`. Key and type never change after creation.
- **Tag name:** 1 to 50 characters after trimming, unique ignoring case.
- **Text value:** at most 1000 characters.
- **Python verification (CI form):** `.venv/Scripts/ruff.exe check <files>`, `.venv/Scripts/mypy.exe netcontrol templates` (baseline: 7 errors in `cloud_*.py` on a clean tree; no new ones), `.venv/Scripts/bandit.exe -q -c bandit.yaml -r netcontrol routes templates -ll -ii`, and `PLEXUS_TEST_PG_URL=postgresql://plexus@127.0.0.1:55432/plexus_test APP_SECRET_KEY=test-secret .venv/Scripts/pytest.exe <test files> -p no:cacheprovider -rfE`. The scratch Postgres on port 55432 is started by the session lead before backend work begins. Run only the test files a task names.
- **Frontend verification (CI form), from `netcontrol/static/frontend`:** `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`.

## Wire Contract

Both the backend and the frontend tasks build against these shapes.

```
Tag            {id, name, color, description}
TagWithUsage   Tag + {usage: {host: int, group: int, prefix: int}}
TagRef         {id, name, color}
Field          {id, key, label, field_type, choices: string[], object_types: string[],
                required: bool, default_value: string, description, sort_order: int}
ObjectData     {tags: TagRef[], fields: {<key>: string | number | boolean}}
ObjectDataPut  {tag_ids: int[], fields: {<key>: string | number | boolean | null}}
```

- `ObjectData.fields` holds stored values only (no defaults), typed: `number` as a JSON number, `boolean` as a JSON boolean, the rest as strings.
- `ObjectDataPut` is a full replace: tags become exactly `tag_ids`; a field that is absent, `null` or `""` is cleared.
- Inline on list rows the same data appears as two properties: `tags: TagRef[]` and `custom_fields: {<key>: value}`.
- Validation failure: HTTP 400, `detail = {"message": str, "fields": {<key>: str}}`. Nothing is written.
- Duplicate tag name or field key: HTTP 409. Unknown id: 404.

## Review Focus

1. A prefix addressed with host bits set or different spelling (`192.0.2.5/24`, `2001:DB8::/32`) must land on the same data as its canonical form. Test in Task 2.
2. A `select` value whose choice was later removed still displays, and a save that resubmits it is rejected with a message naming the field. Tests in Tasks 3 and 5.
3. A list with more objects than one SQL `IN` list should carry (2,000 hosts) still returns inline data, in two queries. Test in Task 3.
4. A tag name or text value that starts with `=`, `+`, `-` or `@` must not become a spreadsheet formula in the CSV export. Test in Task 6.
5. A save that names a field deleted since the form was opened, or a tag id that no longer exists, is rejected whole: 400, the key or id named, nothing written. Test in Task 5.

---

### Task 1: Value validation module

**Files:**
- Create: `netcontrol/custom_fields.py`
- Test: `tests/test_custom_fields_validation.py`

**Interfaces:**
- Produces:
  - `OBJECT_TYPES: tuple[str, ...]`, `FIELD_TYPES: tuple[str, ...]`, `TAG_COLORS: tuple[str, ...]`, `FIELD_KEY_RE`, `TEXT_MAX = 1000`, `TAG_NAME_MAX = 50`
  - `class CustomFieldError(ValueError)`
  - `canonical_value(field: dict, raw: object) -> str` — stored text for `raw`, `""` when `raw` is `None` or blank; raises `CustomFieldError` whose message starts with the field's label.
  - `typed_value(field_type: str, stored: str) -> str | int | float | bool`
  - `clean_tag_name(raw: str) -> str` — trimmed; raises `CustomFieldError` when empty or over 50.

- [ ] **Step 1: Write the failing tests**

```python
F = lambda t, **kw: {"key": "k", "label": "Owner", "field_type": t, "choices": [], **kw}

@pytest.mark.parametrize("ftype,raw,stored", [
    ("text", "  core team ", "core team"),
    ("number", "10.50", "10.5"), ("number", 7, "7"), ("number", "-0", "0"),
    ("boolean", True, "true"), ("boolean", "false", "false"),
    ("date", "2026-02-28", "2026-02-28"),
    ("url", " https://example.com/x ", "https://example.com/x"),
    ("text", None, ""), ("number", "", ""),
])
def test_canonical(ftype, raw, stored):
    assert canonical_value(F(ftype), raw) == stored

@pytest.mark.parametrize("ftype,raw", [
    ("text", "x" * 1001), ("number", "abc"), ("number", "nan"), ("number", "inf"),
    ("boolean", "maybe"), ("date", "2026-02-30"), ("date", "02/28/2026"),
    ("url", "ftp://example.com"), ("url", "https://"), ("url", "javascript:alert(1)"),
])
def test_rejects(ftype, raw):
    with pytest.raises(CustomFieldError, match="^Owner"):
        canonical_value(F(ftype), raw)

def test_select():
    f = F("select", choices=["prod", "lab"])
    assert canonical_value(f, "lab") == "lab"
    with pytest.raises(CustomFieldError):
        canonical_value(f, "dev")

def test_typed():
    assert typed_value("number", "7") == 7 and typed_value("number", "10.5") == 10.5
    assert typed_value("boolean", "true") is True and typed_value("date", "2026-02-28") == "2026-02-28"

def test_tag_name():
    assert clean_tag_name("  pci-scope ") == "pci-scope"
    for bad in ("", "   ", "t" * 51):
        with pytest.raises(CustomFieldError):
            clean_tag_name(bad)
```

- [ ] **Step 2: Run** `pytest tests/test_custom_fields_validation.py` — expect import failure.
- [ ] **Step 3: Implement the module.** Numbers go through `decimal.Decimal` (reject non-finite, `normalize`, format without exponent). URLs through `urllib.parse.urlsplit`: scheme `http` or `https` and a non-empty host.
- [ ] **Step 4: Run** the test file — expect all pass. Run `ruff check` on both files.

---

### Task 2: Tables and definition storage

**Files:**
- Create: `routes/migrations/0083_add_custom_fields_and_tags.py`, `routes/db/custom_fields.py`
- Modify: `routes/database.py` (module docstring table list near line 43, `SCHEMA`, star import near line 2964)
- Test: `tests/test_custom_fields_db.py`

**Interfaces:**
- Consumes: Task 1 constants and `CustomFieldError`.
- Produces (all `async`, all re-exported by `routes.database`):
  - `prefix_key(subnet: str, vrf: str | None = "") -> str` (sync) — `f"{ipaddress.ip_network(subnet, strict=False)}|{vrf.strip()}"`; raises `ValueError` on a bad subnet.
  - `list_tags(with_usage: bool = False) -> list[dict]`, `get_tag(tag_id: int) -> dict | None`
  - `create_tag(*, name: str, color: str = "gray", description: str = "", created_by: str = "") -> dict` — raises `ValueError` when the name is taken ignoring case.
  - `update_tag(tag_id: int, *, name: str, color: str, description: str) -> dict | None`, `delete_tag(tag_id: int) -> int` (assignments removed)
  - `list_custom_fields(object_type: str | None = None) -> list[dict]` ordered by `sort_order, id`; `get_custom_field(field_id: int) -> dict | None`
  - `create_custom_field(*, key, label, field_type, choices: list[str], object_types: list[str], required: bool, default_value: str, description: str, sort_order: int, created_by: str) -> dict` — `ValueError` on a taken key.
  - `update_custom_field(field_id: int, *, label, choices, object_types, required, default_value, description, sort_order) -> dict | None` — deletes values on object types that were removed.
  - `count_custom_field_values(field_id: int, object_types: list[str] | None = None) -> int`
  - `delete_custom_field(field_id: int) -> int` (values removed)
  - Rows come back in the Wire Contract shapes (`choices`, `object_types` as lists, `required` as bool).

- [ ] **Step 1: Write the migration and the `SCHEMA` block.** Follow `0082_add_mcp_tokens.py` for dialect and layout, and the existing `SCHEMA` entries for theirs. Tables and columns exactly as the spec's Data model section. Indexes: unique `idx_tags_name_lower` on `lower(name)`; unique `(tag_id, object_type, object_key)` and index `(object_type, object_key)` on `tag_assignments`; the same pair on `custom_field_values` with `field_id`; unique `key` on `custom_fields`. Foreign keys cascade on delete.
- [ ] **Step 2: Write the failing tests** (async style and fixtures as in `tests/test_mcp_tokens_db.py`):

```python
async def test_tag_names_are_unique_ignoring_case():
    await db.create_tag(name="PCI-Scope")
    with pytest.raises(ValueError):
        await db.create_tag(name="pci-scope")

async def test_tag_round_trip_and_usage():
    tag = await db.create_tag(name="core", color="blue", description="core sites")
    assert tag == {"id": tag["id"], "name": "core", "color": "blue", "description": "core sites"}
    (listed,) = await db.list_tags(with_usage=True)
    assert listed["usage"] == {"host": 0, "group": 0, "prefix": 0}

async def test_field_round_trip_and_object_type_filter():
    f = await db.create_custom_field(key="owner", label="Owner", field_type="select",
        choices=["net", "sec"], object_types=["host", "prefix"], required=True,
        default_value="net", description="", sort_order=5, created_by="admin")
    assert f["choices"] == ["net", "sec"] and f["required"] is True
    assert [x["key"] for x in await db.list_custom_fields("host")] == ["owner"]
    assert await db.list_custom_fields("group") == []

async def test_duplicate_field_key_raises():  # second create_custom_field(key="owner") -> ValueError

def test_prefix_key_is_canonical():
    assert db.prefix_key("192.0.2.5/24", " blue ") == "192.0.2.0/24|blue"
    assert db.prefix_key("2001:DB8::/32") == "2001:db8::/32|"
    with pytest.raises(ValueError):
        db.prefix_key("not-a-subnet")
```

- [ ] **Step 3: Run** `pytest tests/test_custom_fields_db.py` — expect failures on missing functions.
- [ ] **Step 4: Implement** `routes/db/custom_fields.py` in the style of `routes/db/mcp_tokens.py` (module docstring, `__all__`, `_dbcore.get_db()`, `RETURNING id`, `_is_unique_violation`), and add the star import to `routes/database.py`.
- [ ] **Step 5: Run** the test file — expect pass. Run `ruff check` on the changed files.

---

### Task 3: Object data storage and delete cleanup

**Files:**
- Modify: `routes/db/custom_fields.py`, `routes/db/inventory.py` (`delete_group` ~455, `remove_host` ~709, `bulk_delete_hosts` ~810)
- Test: `tests/test_custom_fields_db.py`

**Interfaces:**
- Consumes: Task 2 functions.
- Produces:
  - `get_object_data(object_type: str, object_key: str) -> dict` — `{"tags": [TagRef], "fields": {key: stored_text}}`
  - `get_object_data_bulk(object_type: str, object_keys: list[str] | None = None) -> dict[str, dict]` — same value per key; keys with no data are absent. Two queries. With more than 1,000 keys, or `None`, it selects by `object_type` alone and filters in Python.
  - `set_object_data(object_type: str, object_key: str, tag_ids: list[int], values: dict[int, str]) -> None` — full replace in one transaction; `values` maps field id to canonical text, empty text removes. Raises `ValueError` naming the id when a tag id or field id does not exist.
  - `bulk_update_tags(object_type: str, object_keys: list[str], add_tag_ids: list[int], remove_tag_ids: list[int]) -> int` — number of objects touched.
  - `find_object_keys(object_type: str, tag_names: list[str], field_filters: dict[int, str]) -> set[str]` — keys carrying every tag (names matched ignoring case) and every field value.
  - `purge_object_data(db, object_type: str, object_keys: list[str]) -> None` — runs on the caller's open connection, does not commit.

Storage returns stored text; converting to typed values is the API layer's job (Task 4, with `typed_value` from Task 1).

- [ ] **Step 1: Write the failing tests.** Create hosts and groups with `db.create_group` / `db.add_host`; use `192.0.2.x` addresses.

```python
async def test_set_get_replace():
    # set tags [a, b] and owner="net" on host h; get returns both tags (name order) and {"owner": "net"}
    # set again with tag_ids=[b], values={owner_id: ""} -> tags == [b], fields == {}

async def test_set_rejects_unknown_ids_and_writes_nothing():
    # set_object_data("host", key, [999999], {}) -> ValueError matching "999999"; data unchanged

async def test_bulk_matches_single_and_handles_2000_keys():
    # tag host h; keys = [str(i) for i in range(1, 2001)] + [str(h)]
    # get_object_data_bulk("host", keys) == {str(h): await get_object_data("host", str(h))}

async def test_bulk_update_tags_adds_and_removes():
async def test_find_object_keys_requires_every_tag_and_value():
    # h1: tags a,b owner=net; h2: tag a owner=sec
    # find("host", ["A", "b"], {}) == {h1}; find("host", ["a"], {owner_id: "sec"}) == {h2}; find("host", [], {}) == set()

async def test_tag_usage_counts():
    # after tagging one host and one prefix: usage == {"host": 1, "group": 0, "prefix": 1}

async def test_removing_object_type_from_field_deletes_those_values():
async def test_host_delete_purges(): # remove_host -> get_object_data_bulk("host", [key]) == {}
async def test_bulk_host_delete_purges():
async def test_group_delete_purges_group_and_its_hosts():
async def test_moving_a_host_keeps_its_data(): # db.move_hosts
async def test_prefix_data_survives_a_source_resync():
    # create an ipam source, replace_ipam_source_snapshot with 192.0.2.0/24, tag prefix_key("192.0.2.0/24"),
    # replace_ipam_source_snapshot again -> get_object_data("prefix", key)["tags"] still has the tag
```

- [ ] **Step 2: Run** — expect failures.
- [ ] **Step 3: Implement** the storage functions, then call `purge_object_data` inside the existing transactions: in `remove_host` and `bulk_delete_hosts` before the commit; in `delete_group` select the group's host ids first, then purge those and the group key before the commit.
- [ ] **Step 4: Run** `tests/test_custom_fields_db.py` and the existing inventory db tests that cover the three delete functions (find them with `grep -l "bulk_delete_hosts\|delete_group\|remove_host" tests/`) — expect pass. `ruff check` the changed files.

---

### Task 4: API routers

**Files:**
- Create: `netcontrol/routes/custom_fields.py`
- Modify: `netcontrol/app.py` (import near line 228, registration beside the inventory and IPAM routers), `AUTHORIZATION_MATRIX.md`, `tools/coverage_gate.py`
- Test: `tests/test_custom_fields_api.py`

**Interfaces:**
- Consumes: Tasks 1 to 3.
- Produces four routers in one module, registered in `app.py` as shown:

| Router | Registered with | Routes |
|---|---|---|
| `router` | `require_auth` | `GET /api/custom-fields` (`?object_type=`), `GET /api/tags` (TagWithUsage list) |
| `admin_router` | `require_admin` | `POST /api/custom-fields` (201), `PUT`/`DELETE /api/custom-fields/{field_id}`, `PUT`/`DELETE /api/tags/{tag_id}` |
| `inventory_router` | `require_auth`, `require_feature("inventory")` | `POST /api/tags` (201), `GET`/`PUT /api/hosts/{host_id}/custom-data`, `GET`/`PUT /api/inventory/{group_id}/custom-data`, `POST /api/hosts/bulk-tags` |
| `ipam_router` | `require_auth`, `require_feature_method("ipam")` | `GET`/`PUT /api/ipam/prefix-custom-data?subnet=&vrf=`; the `PUT` also depends on admin through an `init_custom_fields(require_admin)` hook, the way `netcontrol/routes/ipam.py` does it |

  Also produces, for Task 5: `async def attach_custom_data(object_type: str, rows: list[dict], key_of: Callable[[dict], str]) -> None` (sets `tags` and `custom_fields` on each row from one `get_object_data_bulk` call, typed values) and `async def matching_keys(object_type: str, query_params) -> set[str] | None` (`None` when the request has no `tag=` or `cf.` parameter; raises HTTP 400 on an unknown `cf.` key or a value the field's type rejects).

- Behaviour the tests pin:
  - `PUT` on an object validates every submitted field with `canonical_value`, rejects keys that are unknown or not applicable to the object type, enforces `required` (a required applicable field must have a submitted value or a default), collects all field errors into one 400, and writes nothing on failure.
  - `PUT`/`GET` on a host or group that does not exist: 404. Prefix with a bad subnet: 400.
  - `PUT /api/custom-fields/{id}` ignores `key` and `field_type` in the body. When the change removes object types that hold values it returns 409 with `detail = {"message": ..., "affected": n}` unless `?confirm=true`. `DELETE` on a field or tag returns `{"ok": true, "removed": n}`.
  - `POST /api/hosts/bulk-tags` body `{host_ids: int[], add_tag_ids: int[], remove_tag_ids: int[]}`; at most 5,000 host ids.
  - `POST /api/tags` with a name that exists ignoring case returns 409.
  - Every write calls `_audit("custom_fields", <action>, user=..., detail=..., correlation_id=...)` with actions `field_create`, `field_update`, `field_delete`, `tag_create`, `tag_update`, `tag_delete`, `object_update`, `bulk_tags`.

- [ ] **Step 1: Write the failing tests** using `admin_client` and `user_client` from `tests/mcp_helpers.py`. To give a non-admin the `inventory` feature, use whatever the existing access tests use (grep `tests/` for `access-groups`). Cases:

```python
def test_definitions_need_admin_to_write():      # user: POST /api/custom-fields -> 403; GET -> 200
def test_anonymous_is_rejected():                # no session: GET /api/tags -> 401
def test_user_without_inventory_cannot_touch_host_data():   # GET and PUT -> 403
def test_user_with_inventory_can_tag_and_create_tags():     # POST /api/tags 201, PUT host custom-data 200
def test_prefix_write_needs_admin():             # user with ipam.write: PUT -> 403; admin -> 200
def test_field_create_validation():              # bad key "Owner", unknown type, select with no choices,
                                                 # unknown object type, default not valid for the type -> 422
def test_key_and_type_are_fixed():               # PUT with key/field_type changed -> stored values unchanged
def test_put_round_trip_typed():                 # number 10.50 -> GET fields == {"rack_units": 10.5}; boolean -> True
def test_put_collects_all_field_errors():        # two bad values -> 400, detail["fields"] has both keys, nothing stored
def test_required_enforced_only_on_custom_data_save():
    # required field with no default: PUT {} -> 400; PUT /api/hosts/{id} rename still 200
    # required field with default "net": PUT {} -> 200 and GET fields == {} (default not written)
def test_stale_select_value_is_shown_then_rejected():
    # store "lab", admin removes "lab" from choices: GET still shows "lab"; PUT resubmitting "lab" -> 400 naming the label
def test_unknown_field_key_or_tag_id_rejects_whole_save():
    # PUT {tag_ids: [good, 999999], fields: {"gone": "x"}} -> 400 naming both; object data unchanged
def test_removing_object_type_needs_confirm():   # 409 with affected == 1, then ?confirm=true -> 200 and value gone
def test_delete_reports_removed_count():
def test_bulk_tags():
def test_missing_objects_404_and_bad_subnet_400():
def test_prefix_key_spellings_share_data():      # PUT subnet=192.0.2.5/24, GET subnet=192.0.2.0/24 -> same tags
def test_writes_are_audited():                   # audit rows with category custom_fields for each action
```

- [ ] **Step 2: Run** `pytest tests/test_custom_fields_api.py` — expect 404s.
- [ ] **Step 3: Implement** the module (pydantic bodies with `Field` limits, as `netcontrol/routes/mcp_tokens.py`) and register the routers and `init_custom_fields(require_admin)` in `app.py`.
- [ ] **Step 4: Add** every new route to `AUTHORIZATION_MATRIX.md` in that file's existing format, and floors to `tools/coverage_gate.py`: `"netcontrol/custom_fields.py": 95.0`, `"netcontrol/routes/custom_fields.py": 85.0`. If the measured figure is below a floor, add tests; do not lower the floor.
- [ ] **Step 5: Run** the API test file plus any test that checks the authorization matrix against the route table (grep `tests/` for `AUTHORIZATION_MATRIX`) — expect pass. Run `ruff check` on changed files, `mypy netcontrol templates`, and the `bandit` command.

---

### Task 5: Inline data and filters on existing endpoints

**Files:**
- Modify: `netcontrol/routes/inventory.py` (`list_groups` ~1178, `get_group` ~1264, `list_hosts` ~1285), `netcontrol/routes/ipam.py` (`ipam_overview_api` ~131, `ipam_subnet_detail_api` ~213)
- Test: `tests/test_custom_fields_api.py`

**Interfaces:**
- Consumes: `attach_custom_data`, `matching_keys` from Task 4; `prefix_key` from Task 2.
- Produces: `tags` and `custom_fields` on every group, host and subnet row those endpoints return (empty list and empty object when there is none).

Filter semantics, for `tag=` (repeatable) and `cf.<key>=<value>`:
- `GET /api/inventory?include_hosts=true`: each group keeps only its matching hosts; groups left with no hosts are dropped.
- `GET /api/inventory` without hosts: only matching groups.
- `GET /api/inventory/{group_id}/hosts`: only matching hosts.
- `GET /api/ipam/overview`: only matching subnets in the subnet list; summary counts are left as computed. Subnet key is `prefix_key(row["subnet"], row.get("vrf_name"))`.

- [ ] **Step 1: Write the failing tests**

```python
def test_inventory_lists_carry_inline_data():    # both include_hosts modes and /hosts; untagged rows have [] and {}
def test_inventory_tag_and_field_filters():      # two hosts, one tagged: ?include_hosts=true&tag=core returns one group with one host
def test_filter_values_are_canonicalised():      # cf.rack_units=10.50 matches a stored 10.5
def test_unknown_filter_key_is_400():            # ?cf.nope=x
def test_ipam_overview_and_subnet_detail_carry_inline_data():
def test_ipam_overview_tag_filter():
```

- [ ] **Step 2: Run** — expect failures. **Step 3: Implement.** The list handlers gain a `request: Request` parameter where they lack one, to read `request.query_params`. **Step 4: Run** `tests/test_custom_fields_api.py` and the existing test files for the inventory and IPAM routes (grep `tests/` for `/api/ipam/overview` and `/api/inventory"`) — expect pass. `ruff check`, `mypy`.

---

### Task 6: CSV export columns

**Files:**
- Modify: `netcontrol/routes/inventory.py` (`export_inventory_csv` ~1205); `routes/db/inventory.py` only if `get_all_hosts_for_export` does not return host ids
- Test: `tests/test_custom_fields_api.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_csv_has_tags_and_field_columns():
    # header ends with: "Group", "Tags", then one column per host-applicable field label in sort_order
    # a host tagged core and edge shows "core; edge"; a group-only field has no column
def test_csv_cells_cannot_start_a_formula():
    # tag named "=cmd" and text value "@SUM(A1)" are written with a leading apostrophe; a number value -5 is written as -5
```

- [ ] **Step 2: Run** — expect failure. **Step 3: Implement.** Grep for an existing CSV cell sanitiser first (`formula`, `csv` in `netcontrol/` and `routes/`); reuse it if there is one, otherwise add one small function beside the export and apply it to the tag and text cells. **Step 4: Run** the test file — expect pass.

---

### Task 7: Frontend API module and shared components

**Files:**
- Create: `src/api/customData.ts`, `src/components/TagChips.tsx`, `src/components/TagPicker.tsx`, `src/components/CustomFieldsForm.tsx`, `src/components/CustomDataFilter.tsx`, `src/lib/customData.ts`, `src/lib/customData.test.ts`, `src/components/TagPicker.test.tsx`, `src/components/CustomFieldsForm.test.tsx`
- Modify: `src/api/inventory.ts` (`InventoryHost`, `InventoryGroupFull`), `src/api/ipam.ts` (`IpamSubnet`): add `tags?: TagRef[]` and `custom_fields?: Record<string, CustomValue>`; `src/api/client.ts` only if its error type cannot carry a structured `detail`

(All paths under `netcontrol/static/frontend/`.)

**Interfaces:**
- Consumes: the Wire Contract.
- Produces:
  - `api/customData.ts`: types `Tag`, `TagWithUsage`, `TagRef`, `CustomField`, `CustomValue = string | number | boolean`, `ObjectData`, `ObjectDataPut`, `ObjectRef = {type: 'host'; id: number} | {type: 'group'; id: number} | {type: 'prefix'; subnet: string; vrf?: string}`; hooks `useTags()`, `useCustomFields(objectType?)`, `useObjectData(ref, enabled?)`, `useSaveObjectData()` (takes `{ref, data: ObjectDataPut}`), `useCreateTag()`, `useUpdateTag()`, `useDeleteTag()`, `useCreateCustomField()`, `useUpdateCustomField()` (takes `confirm?: boolean`), `useDeleteCustomField()`, `useBulkTagHosts()`. Mutations invalidate the tag, field, inventory and IPAM overview queries they affect. A 400 from a save surfaces `detail.fields` to the caller.
  - `lib/customData.ts` (pure): `TAG_COLORS`, `interface CustomDataFilterValue {tagIds: number[]; fields: Record<string, string>}` (field value `'*'` means "has any value"), `matchesCustomData(row: {tags?: TagRef[]; custom_fields?: Record<string, CustomValue>}, filter: CustomDataFilterValue): boolean`, `isEmptyFilter(filter)`, `initialFieldValues(fields: CustomField[], stored: Record<string, CustomValue>): Record<string, CustomValue | ''>` (stored value, else default, else `''`).
  - `<TagChips tags={TagRef[]} max?={number} />` — read-only; beyond `max` shows `+n`.
  - `<TagPicker value={number[]} onChange={(ids: number[]) => void} canCreate={boolean} />` — type-ahead over `useTags()`; when nothing matches and `canCreate`, a "Create tag "<text>"" option that calls `useCreateTag` and selects the result.
  - `<CustomFieldsForm objectType={...} values={Record<string, CustomValue | ''>} onChange={...} errors?={Record<string, string>} />` — one labelled input per applicable field in `sort_order`: text input, number input, checkbox, date input, URL input, select with an empty option. Visible label on every input, required marker, description as help text, error under the field with `FieldError`. A stored `select` value that is no longer a choice is shown as an extra option marked "(removed)". Renders nothing when no field applies.
  - `<CustomDataFilter objectType={...} value={CustomDataFilterValue} onChange={...} />` — a menu button "Filter" with a count badge; lists tags as checkboxes, `select` and `boolean` fields as choices, other fields as "has a value".
  - Chip colors come from theme tokens, one pair per palette slot, defined once where the app defines its other color tokens (see `lib/themeColors.ts` and the stylesheet it reads); each must hold contrast in the light and dark themes.

- [ ] **Step 1: Write the failing tests**

```ts
// lib/customData.test.ts
it('matches every selected tag', ...)            // row tags [1,2]: filter [1,2] true, [1,3] false
it('matches field equality and has-value', ...)  // {env:'prod'}: fields {env:'prod'} true, {env:'lab'} false, {env:'*'} true, {owner:'*'} false
it('compares booleans and numbers as text', ...) // custom_fields {managed:true, units:2}: {managed:'true'} and {units:'2'} true
it('an empty filter matches everything', ...)
it('initial values prefer stored, then default, then empty', ...)

// TagPicker.test.tsx
it('offers Create only when nothing matches and canCreate', ...)
it('adds and removes a tag', ...)

// CustomFieldsForm.test.tsx
it('renders an input of the right kind for each of the six types', ...)
it('shows the error under its field', ...)
it('keeps a removed select choice visible', ...)
it('renders nothing when no field applies', ...)
```

- [ ] **Step 2: Run** `npm test -- customData TagPicker CustomFieldsForm` — expect failure. **Step 3: Implement.** Follow `api/ipam.ts` for hook style and the existing component tests for the test setup. **Step 4: Run** `npm test`, `npm run lint`, `npm run typecheck` — expect pass.

---

### Task 8: Inventory page

**Files:**
- Modify: `src/pages/Inventory/HostModal.tsx`, `GroupModal.tsx`, `Inventory.tsx`, `helpers.ts`, `helpers.test.ts`
- Create: `src/pages/Inventory/BulkTagModal.tsx`

**Interfaces:**
- Consumes: Task 7.

Behaviour:
- `HostModal` and `GroupModal` gain a "Tags and custom fields" section below the existing inputs: `TagPicker` (`canCreate` true) and `CustomFieldsForm`. In edit mode the section loads with `useObjectData`; in create mode it starts from defaults. Submit saves the object first, then its custom data against the returned id; if the second call fails the modal stays open, shows the field errors, and a retry sends only the custom data.
- Group headers and host rows show `TagChips` (`max={3}`).
- `CustomDataFilter` sits beside the search box; it combines with the text search (both must match). A group that matches by its own tags or fields is shown with all its hosts; a group that matches only through its hosts is shown with only those hosts. The empty state for a filter with no matches says so and offers "Clear filter".
- The bulk action bar for selected hosts gains "Tag…", opening `BulkTagModal`: two `TagPicker`s, "Add" and "Remove", applying `useBulkTagHosts` to the selection.
- Put the group/host filter predicate in `helpers.ts` as `filterGroupsByCustomData(groups, filter)` and test it there.

- [ ] **Step 1: Write the failing test** in `helpers.test.ts`: a group that matches by its own tags or fields keeps all its hosts; a group that matches only through its hosts keeps only those hosts; a group with no match of either kind is dropped; an empty filter returns the input unchanged.
- [ ] **Step 2: Run** `npm test -- Inventory/helpers` — expect failure. **Step 3: Implement.** **Step 4: Run** `npm test`, `npm run lint`, `npm run typecheck`.

---

### Task 9: IPAM page

**Files:**
- Modify: `src/pages/Ipam/Ipam.tsx`, `SubnetDrilldown.tsx`, `helpers.ts`, `helpers.test.ts`

**Interfaces:**
- Consumes: Task 7.

Behaviour:
- Subnet rows show `TagChips` (`max={3}`); `CustomDataFilter` (`objectType="prefix"`) sits beside the existing filters and combines with them.
- `SubnetDrilldown` gains a "Tags and custom fields" panel for `{type: 'prefix', subnet, vrf}`: read-only chips and values for everyone; admins get an "Edit" button that switches the panel to `TagPicker` + `CustomFieldsForm` with "Save" and "Cancel". Use whatever the page already uses to know the viewer is an admin.

- [ ] **Step 1: Write the failing test** in `helpers.test.ts` for the subnet filter predicate added to `helpers.ts` (`filterSubnetsByCustomData(subnets, filter)`): filters by tag and by field; empty filter returns the input unchanged.
- [ ] **Step 2: Run** — expect failure. **Step 3: Implement.** **Step 4: Run** `npm test`, `npm run lint`, `npm run typecheck`.

---

### Task 10: Settings tab

**Files:**
- Create: `src/pages/Settings/CustomDataTab.tsx`, `CustomFieldModal.tsx`, `TagModal.tsx`
- Modify: `src/pages/Settings/Settings.tsx` (`Tab` type, `TAB_HELP`, `ADMIN_TABS`, render switch)

**Interfaces:**
- Consumes: Task 7.

Behaviour:
- New admin tab, key `custom-data`, label "Custom Fields & Tags", placed after "Features". `TAB_HELP` text: "Define extra fields and tags for hosts, groups and IPAM prefixes. Values are set on the object itself."
- Two sections, each a table with a "New field" / "New tag" button and row actions Edit and Delete:
  - Fields: Label, Key, Type, Applies to, Required, Order.
  - Tags: chip, Description, Used on (sum of usage, with the per-type split in a tooltip).
- `CustomFieldModal`: key and type are editable on create and read-only on edit; choices editor appears for `select` (one per line); default value uses the input for the chosen type. A 409 with `affected` on save opens a confirm naming the count ("Remove this field from groups? 4 groups lose their value.") and retries with `confirm`.
- Delete confirmations name the count: "Delete field "Owner"? 12 objects lose their value." / "Delete tag "core"? It is removed from 12 objects."
- Empty states: "No custom fields yet." with "New field"; "No tags yet." with "New tag".
- Buttons are verb-first; the tab follows `AiAccessTab.tsx` and `McpTokenModal.tsx` for structure.

- [ ] **Step 1: Implement.** **Step 2: Run** `npm test`, `npm run lint`, `npm run typecheck`, `npm run build` — expect pass.

---

### Task 11: Documentation and full verification

**Files:**
- Create: `docs/custom-fields-and-tags.md`
- Modify: `README.md` (feature list), the spec's `Status:` line to `implemented`

- [ ] **Step 1: Write** `docs/custom-fields-and-tags.md`: what the feature is, the six field types with their accepted input, the rules (required, default, removed choices, what deletion removes, prefix identity by subnet and VRF), who can do what, and the API with one request and response example per route using invented data.
- [ ] **Step 2: Add** one line to the README feature list.
- [ ] **Step 3: Grep** every new and changed file for real hostnames, addresses, account ids or names seen during the work; replace any hit.
- [ ] **Step 4: Run once, CI form:** `ruff check .`, `mypy netcontrol templates`, the `bandit` command, the full `pytest` run with the CI coverage flags (`--cov=netcontrol --cov=routes --cov-report=term-missing --cov-report=json:coverage.json --cov-fail-under=30`) followed by `python tools/coverage_gate.py coverage.json`, and in the frontend `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`. The change touches `routes/database.py` and adds a migration, so the full suite is warranted here, once.

## Execution order

Tasks 1 to 6 (backend) run in order. Tasks 7 to 10 (frontend) run in order and depend only on the Wire Contract, so the frontend sequence runs in parallel with the backend sequence. Task 11 runs last.
