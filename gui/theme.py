"""Black & red palette and helpers for the NetReplay GUI."""
from __future__ import annotations

import flet as ft

RED = "#ef4444"
RED_DARK = "#a5122a"
RED_SOFT = "#f87171"
RED_WARM = "#ff8a65"
AMBER = "#ffd54f"
PANEL = "#141417"
PANEL_HIGH = "#1c1c20"
BLACK = "#0a0a0c"
BLACK_SOFT = "#0e0d10"
TEXT = "#ececf0"
MUTED = "#8f8f97"
DIVIDER = "#26262c"

GRADIENT = ["#170e10", "#0c0c0e", "#100a0b"]


def red_tint(opacity: float) -> str:
    return ft.Colors.with_opacity(opacity, RED)


def muted_red(opacity: float) -> str:
    return ft.Colors.with_opacity(opacity, RED_SOFT)


def build_theme() -> ft.Theme:
    return ft.Theme(
        color_scheme=ft.ColorScheme(
            primary=RED,
            on_primary="#ffffff",
            primary_container="#3a1314",
            on_primary_container="#ffd9d9",
            secondary=RED_SOFT,
            on_secondary="#240708",
            secondary_container="#3a2020",
            on_secondary_container="#ffdcdc",
            tertiary=RED_WARM,
            on_tertiary="#1d0a03",
            error=RED,
            on_error="#ffffff",
            error_container="#401214",
            on_error_container="#ffdada",
            surface=PANEL,
            on_surface=TEXT,
            surface_container_lowest=BLACK,
            surface_container_low=BLACK_SOFT,
            surface_container=PANEL,
            surface_container_high=PANEL_HIGH,
            surface_container_highest="#242428",
            on_surface_variant=MUTED,
            outline=DIVIDER,
            outline_variant="#2c2c32",
            inverse_primary=RED_SOFT,
            shadow="#000000",
            scrim="#000000",
        ),
        visual_density=ft.VisualDensity.COMFORTABLE,
    )