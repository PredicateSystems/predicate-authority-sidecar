//! Visual theme: dark palette, spacing, and typography tuned for a small desktop tool.

use egui::{Color32, CursorIcon, FontFamily, FontId, Margin, Rounding, Stroke, TextStyle, Visuals};

pub const ACCENT: Color32 = Color32::from_rgb(52, 132, 168);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(38, 98, 128);
pub const OK: Color32 = Color32::from_rgb(86, 178, 112);
pub const MUTED: Color32 = Color32::from_rgb(150, 158, 172);

pub fn apply(ctx: &egui::Context) {
    let mut v = Visuals::dark();
    v.dark_mode = true;

    v.window_rounding = Rounding::same(10.0);
    v.window_fill = Color32::from_rgb(26, 28, 34);
    v.window_stroke = Stroke::new(1.0, Color32::from_rgb(48, 52, 62));
    v.panel_fill = Color32::from_rgb(22, 24, 30);
    v.extreme_bg_color = Color32::from_rgb(16, 18, 22);
    v.faint_bg_color = Color32::from_rgb(32, 35, 44);
    v.code_bg_color = Color32::from_rgb(20, 22, 28);

    v.hyperlink_color = Color32::from_rgb(130, 190, 235);
    v.warn_fg_color = Color32::from_rgb(230, 190, 100);
    v.error_fg_color = Color32::from_rgb(235, 110, 110);

    v.selection.bg_fill = ACCENT_DIM;
    v.selection.stroke = Stroke::new(1.0, ACCENT);

    let r = Rounding::same(5.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.rounding = r;
    }

    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(40, 44, 54);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(48, 52, 64);
    v.widgets.active.weak_bg_fill = ACCENT_DIM;

    v.button_frame = true;
    v.collapsing_header_frame = true;
    v.interact_cursor = Some(CursorIcon::PointingHand);

    ctx.set_visuals(v);

    ctx.style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(10.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 7.0);
        s.spacing.indent = 16.0;
        s.spacing.window_margin = Margin::same(12.0);

        s.text_styles.insert(
            TextStyle::Small,
            FontId::new(11.0, FontFamily::Proportional),
        );
        s.text_styles
            .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        s.text_styles.insert(
            TextStyle::Button,
            FontId::new(14.0, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Heading,
            FontId::new(22.0, FontFamily::Proportional),
        );
        s.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(13.0, FontFamily::Monospace),
        );
    });
}
