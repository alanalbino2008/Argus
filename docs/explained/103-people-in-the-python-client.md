# 103. Researching a person from the Python client

Everything the People tab does (101, 102) can be scripted with the Python client, for example to
add the known details of many people from a spreadsheet, or to pull the candidates into another tool.

```python
person = argus.add_person(case_id, "Jane Doe", names=["Jane Doe"], usernames=["jdoe"],
                          emails=["jane@example.org"], city="Leeds", employer="Acme Logistics")
argus.person_photo(case_id, person["id"], open("jane.jpg", "rb").read())
argus.search_person(case_id, person["id"], rounds=2)
person = argus.wait_for_person(case_id, person["id"])
for c in argus.candidates(case_id, person["id"], verdicts=("likely", "possible")):
    print(c["score"], c["verdict"], c["label"], c["agree"], c["conflict"])
```

| Method | What it does |
| --- | --- |
| `people(case)` | the people researched in a case |
| `add_person(case, name, **known)` | add one; a single value is accepted where a list is expected |
| `person(case, id)` | known details, latest search, every candidate (best first) |
| `update_person(case, id, name=, known=)` | rename, or replace the known details |
| `add_known(case, id, **details)` | add to what is known (lists are extended, the rest replaced) |
| `person_photo(case, id, image)` | a known photo; only its fingerprint is kept |
| `search_person(case, id, rounds=, fresh=)` | search from everything known |
| `wait_for_person(case, id)` | block until the search finishes |
| `stop_person_search(case, id)` | stop it |
| `candidates(case, id, status=, verdicts=, min_score=)` | filter the candidates |
| `confirm_candidate(...)`, `reject_candidate(...)`, `reopen_candidate(...)` | review |
| `watch_person(case, id, on=)` | the weekly watch |
| `remove_person(case, id)` | remove the person and what was found for them |

Calling `add_person` and `search_person` confirms a legitimate purpose for researching the person,
as ticking the box does in the web app. The client also gains `put()` for any endpoint, and file
uploads through `request(..., files=...)`.
