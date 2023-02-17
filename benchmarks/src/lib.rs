use plotly::common::{Line, LineShape, Mode, Title};
use plotly::{Layout, Plot, Scatter};

pub fn plot_proofsize(
    clauses: Vec<usize>,
    proof_size: Vec<usize>,
    filename: String,
) {
    let trace = Scatter::new(clauses, proof_size)
        .name("Proof size")
        .mode(Mode::LinesMarkers)
        .line(Line::new().shape(LineShape::Vh));

    let layout = Layout::new()
        .title(Title::new("Proof size growth with the number of clauses"));
    let mut plot = Plot::new();
    plot.add_trace(trace);
    plot.set_layout(layout);
    plot.use_local_plotly();
    plot.write_html(filename);
    plot.show();
}
