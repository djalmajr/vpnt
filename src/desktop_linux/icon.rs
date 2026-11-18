pub(super) fn open_lock_rgba() -> Vec<u8> {
    let mut rgba = vec![0; 32 * 32 * 4];
    for y in 0_i32..32 {
        for x in 0_i32..32 {
            let body = (6..=25).contains(&x) && (15..=27).contains(&y);
            let distance = (x - 15).pow(2) + (y - 10).pow(2);
            let shackle = (36..=81).contains(&distance) && y <= 10 && x <= 22;
            let left_stem = (6..=9).contains(&x) && (9..=16).contains(&y);
            if body || shackle || left_stem {
                let i = ((y * 32 + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
    }
    rgba
}

pub(super) fn open_lock() -> Result<tray_icon::Icon, tray_icon::BadIcon> {
    tray_icon::Icon::from_rgba(open_lock_rgba(), 32, 32)
}
