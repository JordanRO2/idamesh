"""IDA adapter implementing :class:`~idamesh.domain.ports.enum.EnumGateway`.

Backs the ``enum_upsert`` tool. :meth:`upsert` loads the members of an existing
enum type from the local type library (when one of that name is present), merges
each supplied member into that member list — adding an ``edm_t`` when absent,
overwriting its value when present, and leaving members the caller did not mention
untouched — then rebuilds the enum ``tinfo_t`` from the reconciled
``enum_type_data_t`` (``create_enum``) and stores it back under the same name
(``set_named_type`` with ``NTF_REPLACE``). The total member count is read from the
reconciled member list. A name that resolves to a non-enum type, or a member the
type refuses, raises — surfaced by the application as an ``isError`` result. All
``ida_*`` imports are performed lazily inside the method so this module loads
without IDA present.
"""

from __future__ import annotations

from typing import Dict, Mapping


class IdaEnumGateway:
    """:class:`~idamesh.domain.ports.enum.EnumGateway` over the IDA SDK."""

    def upsert(self, name: str, members: Mapping[str, int]) -> int:
        """Create or update enum ``name`` from ``members``; return the member count.

        When an enum of that name already exists its current members are loaded and
        merged with the supplied ones (add-or-overwrite, never drop). When none
        exists the member list starts empty. The reconciled list is turned back into
        an enum type and saved to the local til under ``name``; its member count is
        returned. A name bound to a non-enum type, or a member list the SDK will not
        turn into a type, raises.
        """
        # Lazy SDK import keeps this module importable without IDA present.
        import ida_typeinf

        til = ida_typeinf.get_idati()
        if til is None:
            raise ValueError("the local type library is unavailable")

        # Load the members already on this enum (empty when it does not yet exist).
        data = ida_typeinf.enum_type_data_t()
        existing = ida_typeinf.tinfo_t()
        if existing.get_named_type(til, name):
            if not existing.is_enum():
                raise ValueError(f"{name!r} already exists and is not an enum")
            if not existing.get_enum_details(data):
                raise ValueError(f"cannot read enum details for {name!r}")

        # Index the current members by name so a listed member updates in place
        # rather than duplicating; unlisted members are left where they are.
        index: Dict[str, int] = {
            member.name: position for position, member in enumerate(data)
        }
        for member_name, value in members.items():
            position = index.get(member_name)
            if position is not None:
                data[position].value = value
                continue
            edm = ida_typeinf.edm_t()
            edm.name = member_name
            edm.value = value
            data.push_back(edm)

        # The reconciled member count is read now: ``create_enum`` swaps the member
        # list into the type and leaves ``data`` empty, so it must be captured here.
        member_count = len(data)

        # Rebuild the enum type from the reconciled member list and store it back.
        tif = ida_typeinf.tinfo_t()
        if not tif.create_enum(data):
            raise ValueError(f"cannot build enum {name!r} from its members")

        flags = getattr(ida_typeinf, "NTF_TYPE", 0) | getattr(
            ida_typeinf, "NTF_REPLACE", 0
        )
        code = tif.set_named_type(til, name, flags)
        if code != 0:
            raise ValueError(f"cannot save enum {name!r} (code {code})")

        return member_count
