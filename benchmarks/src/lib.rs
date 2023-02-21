use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use plotly::common::{Line, LineShape, Mode, Title};
use plotly::layout::{Axis, AxisType};
use plotly::{Layout, Plot, Scatter};

pub fn plot_proofsize(
    clauses: Vec<usize>,
    proof_size: Vec<usize>,
    protocol_name: String,
    filename_prefix: String,
) {
    let filename = filename(filename_prefix, &proof_size);
    let trace = Scatter::new(clauses, proof_size)
        .name("Proof size")
        .mode(Mode::LinesMarkers)
        .line(Line::new().shape(LineShape::Spline));

    let title = format!("{}: Communication size growth", protocol_name);
    // Set x-axis to log scale
    let x_axis = Axis::new()
        .type_(AxisType::Log)
        .title(Title::new("Number of clauses"));
    let y_axis = Axis::new().title(Title::new("Communication size (in bytes)"));
    // Set layout
    let layout = Layout::new()
        .title(Title::new(&title))
        .x_axis(x_axis)
        .y_axis(y_axis);
    // Create plot
    let mut plot = Plot::new();
    plot.add_trace(trace);
    plot.set_layout(layout);
    plot.use_local_plotly();
    plot.write_html(filename);
    plot.show();
}

fn filename(prefix: String, proof_sizes: &Vec<usize>) -> String {
    let mut filename = prefix;
    let mut s = DefaultHasher::new();
    proof_sizes.hash(&mut s);
    let suffix = s
        .finish()
        .to_string();
    filename.push_str(&suffix);
    filename.push_str(".html");
    filename
}
