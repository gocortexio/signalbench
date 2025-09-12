// SignalBench - EDR Test Framework
// Easter egg animation module - Dennis Nedry Special

use colored::*;
use std::{thread, time::Duration};

pub fn jurassic_park() {
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");
    
    let face1 = r#"
      .---.
     /     \
    | o _ o |
    |  \0/  |
    |   v   |
     \_____/
    "#;
    
    let face2 = r#"
      .---.
     /     \
    | o _ o |
    |  \0/  |
    |   -   |
     \_____/
    "#;
    
    let colors = vec![
        Color::Red,
        Color::Yellow,
        Color::Green,
        Color::Cyan,
        Color::Blue,
        Color::Magenta,
    ];
    
    let message = "Ah ah ah, you didn't say the magic word!";
    
    for i in 0..5 {
        let color = colors[i % colors.len()];
        let face = if i % 2 == 0 { face1 } else { face2 };
        
        println!("{}", face);
        println!("{}", message.color(color).bold());
        
        thread::sleep(Duration::from_millis(500));
        
        // Clear for next animation frame
        if i < 4 {
            print!("\x1B[2J\x1B[1;1H");
        }
    }
    
    println!("\nACCESS DENIED: Your security clearance is not sufficient.");
    println!("This incident will be reported to GoCortex.io Security.\n");
}