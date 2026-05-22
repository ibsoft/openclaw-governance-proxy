from __future__ import annotations

from dataclasses import dataclass

ALLOWED_PER_PAGE = {10, 25, 50, 100}


@dataclass
class Page:
    items: list
    page: int
    per_page: int
    total: int

    @property
    def total_pages(self) -> int:
        return max(1, (self.total + self.per_page - 1) // self.per_page)

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    @property
    def has_previous(self) -> bool:
        return self.page > 1


def page_params(args) -> tuple[int, int]:
    try:
        page = max(1, int(args.get("page", 1)))
    except Exception:
        page = 1
    try:
        per_page = int(args.get("per_page", 25))
    except Exception:
        per_page = 25
    if per_page not in ALLOWED_PER_PAGE:
        per_page = 25
    return page, per_page


def paginate(query, args) -> Page:
    page, per_page = page_params(args)
    total = query.count()
    items = query.limit(per_page).offset((page - 1) * per_page).all()
    return Page(items=items, page=page, per_page=per_page, total=total)
