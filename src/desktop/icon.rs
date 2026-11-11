use tray_icon::Icon;

pub fn shield() -> Result<Icon, tray_icon::BadIcon> {
    let mut rgba = vec![0_u8; 22 * 22 * 4];
    let points = [
        (11, 2),
        (18, 5),
        (18, 12),
        (16, 16),
        (11, 20),
        (6, 16),
        (4, 12),
        (4, 5),
        (11, 2),
    ];
    for pair in points.windows(2) {
        let ((mut x, mut y), (to_x, to_y)) = (pair[0], pair[1]);
        let dx = i32::abs(to_x - x);
        let sx = if x < to_x { 1 } else { -1 };
        let dy = -i32::abs(to_y - y);
        let sy = if y < to_y { 1 } else { -1 };
        let mut error = dx + dy;
        loop {
            let index = (y as usize * 22 + x as usize) * 4;
            rgba[index + 3] = 255;
            if x == to_x && y == to_y {
                break;
            }
            let twice = 2 * error;
            if twice >= dy {
                error += dy;
                x += sx;
            }
            if twice <= dx {
                error += dx;
                y += sy;
            }
        }
    }
    Icon::from_rgba(rgba, 22, 22)
}
