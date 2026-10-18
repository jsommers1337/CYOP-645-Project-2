"""Desktop interface for offline pcapng security triage."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.error import Scapy_Exception

from analyzer import AnalysisResult, Finding, analyze_capture


class CaptureAnalyzerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Tracewatch | Capture Analyzer")
        self.root.geometry("1120x760")
        self.root.minsize(900, 620)
        self.root.configure(bg="#101a20")
        self.result: AnalysisResult | None = None
        self.findings_by_id: dict[str, Finding] = {}
        self.open_button: ttk.Button
        self.path_label: ttk.Label
        self.findings_tree: ttk.Treeview
        self.detail: tk.Text
        self.protocol_tree: ttk.Treeview
        self.flow_tree: ttk.Treeview
        self.chart_mode: tk.StringVar
        self.figure: Figure
        self.axes: object
        self.canvas: FigureCanvasTkAgg
        self._configure_style()
        self._build_ui()

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#101a20")
        style.configure("Panel.TFrame", background="#17252c")
        style.configure("TLabel", background="#101a20", foreground="#e6edf0", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background="#101a20", foreground="#91a5ad", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#101a20", foreground="#f4f7f8", font=("Segoe UI Semibold", 20))
        style.configure("Metric.TLabel", background="#17252c", foreground="#f4f7f8", font=("Segoe UI Semibold", 16))
        style.configure("MetricCaption.TLabel", background="#17252c", foreground="#91a5ad", font=("Segoe UI", 9))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))
        style.configure("Accent.TButton", background="#59d3b0", foreground="#10211e")
        style.map("Accent.TButton", background=[("active", "#82e3c7"), ("disabled", "#35534b")])
        style.configure("TNotebook", background="#101a20", borderwidth=0)
        style.configure("TNotebook.Tab", background="#17252c", foreground="#91a5ad", padding=(14, 9), font=("Segoe UI Semibold", 9))
        style.map("TNotebook.Tab", background=[("selected", "#24383f")], foreground=[("selected", "#59d3b0")])
        style.configure("Treeview", background="#17252c", fieldbackground="#17252c", foreground="#e6edf0", rowheight=31, borderwidth=0)
        style.configure("Treeview.Heading", background="#24383f", foreground="#b7c8ce", font=("Segoe UI Semibold", 9), relief="flat")
        style.map("Treeview", background=[("selected", "#34554f")])

    def _build_ui(self) -> None:
        header = ttk.Frame(self.root, padding=(24, 20, 24, 12))
        header.pack(fill="x")
        title_block = ttk.Frame(header)
        title_block.pack(side="left")
        ttk.Label(title_block, text="TRACEWATCH", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(title_block, text="Capture Analyzer", style="Title.TLabel").pack(anchor="w", pady=(2, 0))
        self.open_button = ttk.Button(header, text="Open .pcapng", style="Accent.TButton", command=self._choose_file)
        self.open_button.pack(side="right", pady=6)

        self.path_label = ttk.Label(self.root, text="No capture loaded", style="Muted.TLabel", padding=(24, 0, 24, 14))
        self.path_label.pack(fill="x")

        self.metrics_frame = ttk.Frame(self.root, padding=(24, 0, 24, 16))
        self.metrics_frame.pack(fill="x")
        self.metric_labels: dict[str, ttk.Label] = {}
        for key, caption in (("packets", "PACKETS"), ("duration", "DURATION"), ("volume", "CAPTURE SIZE"), ("findings", "FINDINGS")):
            block = ttk.Frame(self.metrics_frame, style="Panel.TFrame", padding=(14, 10))
            block.pack(side="left", fill="x", expand=True, padx=(0, 8))
            value = ttk.Label(block, text="--", style="Metric.TLabel")
            value.pack(anchor="w")
            ttk.Label(block, text=caption, style="MetricCaption.TLabel").pack(anchor="w", pady=(3, 0))
            self.metric_labels[key] = value

        self.status = tk.StringVar(value="Choose a capture to begin offline analysis.")
        ttk.Label(self.root, textvariable=self.status, style="Muted.TLabel", padding=(24, 0, 24, 10)).pack(fill="x")

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.findings_tab = ttk.Frame(self.tabs, padding=12)
        self.protocols_tab = ttk.Frame(self.tabs, padding=12)
        self.visuals_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.findings_tab, text="Findings")
        self.tabs.add(self.protocols_tab, text="Protocols & Flows")
        self.tabs.add(self.visuals_tab, text="Visualizations")
        self._build_findings_tab()
        self._build_protocols_tab()
        self._build_visuals_tab()

    def _build_findings_tab(self) -> None:
        columns = ("severity", "finding", "summary")
        self.findings_tree = ttk.Treeview(self.findings_tab, columns=columns, show="headings", selectmode="browse")
        self.findings_tree.heading("severity", text="LEVEL")
        self.findings_tree.heading("finding", text="FINDING")
        self.findings_tree.heading("summary", text="WHY IT MATTERS")
        self.findings_tree.column("severity", width=90, stretch=False)
        self.findings_tree.column("finding", width=230, stretch=False)
        self.findings_tree.column("summary", width=650)
        self.findings_tree.pack(fill="both", expand=True)
        self.findings_tree.bind("<<TreeviewSelect>>", self._show_finding)
        self.detail = tk.Text(self.findings_tab, height=7, wrap="word", bg="#17252c", fg="#cfdbdf", insertbackground="#59d3b0", relief="flat", padx=12, pady=10, font=("Segoe UI", 10), state="disabled")
        self.detail.pack(fill="x", pady=(10, 0))

    def _build_protocols_tab(self) -> None:
        split = ttk.Panedwindow(self.protocols_tab, orient="horizontal")
        split.pack(fill="both", expand=True)
        left = ttk.Frame(split, padding=(0, 0, 8, 0))
        right = ttk.Frame(split, padding=(8, 0, 0, 0))
        split.add(left, weight=1)
        split.add(right, weight=2)
        ttk.Label(left, text="PROTOCOL BREAKDOWN", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.protocol_tree = ttk.Treeview(left, columns=("protocol", "packets", "bytes"), show="headings")
        for column, label, width in (("protocol", "PROTOCOL", 115), ("packets", "PACKETS", 90), ("bytes", "BYTES", 110)):
            self.protocol_tree.heading(column, text=label)
            self.protocol_tree.column(column, width=width, anchor="w")
        self.protocol_tree.pack(fill="both", expand=True)
        ttk.Label(right, text="TOP FLOWS BY CAPTURED BYTES", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        self.flow_tree = ttk.Treeview(right, columns=("transport", "source", "destination", "bytes"), show="headings")
        for column, label, width in (("transport", "PROTO", 75), ("source", "SOURCE", 190), ("destination", "DESTINATION", 190), ("bytes", "BYTES", 110)):
            self.flow_tree.heading(column, text=label)
            self.flow_tree.column(column, width=width, anchor="w")
        self.flow_tree.pack(fill="both", expand=True)

    def _build_visuals_tab(self) -> None:
        toolbar = ttk.Frame(self.visuals_tab)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(toolbar, text="VIEW", style="Muted.TLabel").pack(side="left", padx=(2, 12))
        self.chart_mode = tk.StringVar(value="I/O graph")
        for label in ("I/O graph", "Flow graph"):
            ttk.Radiobutton(toolbar, text=label, value=label, variable=self.chart_mode, command=self._draw_chart).pack(side="left", padx=(0, 10))
        self.figure = Figure(figsize=(8, 4.5), dpi=100, facecolor="#17252c")
        self.axes = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.visuals_tab)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.axes.set_facecolor("#17252c")
        self.axes.text(0.5, 0.5, "Load a capture to generate a graph", ha="center", va="center", color="#91a5ad", transform=self.axes.transAxes)
        self.canvas.draw()

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a packet capture", filetypes=(("pcapng captures", "*.pcapng"), ("All files", "*.*")))
        if path:
            self._analyze(path)

    def _analyze(self, path: str) -> None:
        self.open_button.configure(state="disabled")
        self.path_label.configure(text=path)
        self.status.set("Reading packets and checking heuristics...")
        worker = threading.Thread(target=self._analysis_worker, args=(path,), daemon=True)
        worker.start()

    def _analysis_worker(self, path: str) -> None:
        try:
            result = analyze_capture(path)
        except (OSError, ValueError, EOFError, Scapy_Exception) as error:
            self.root.after(0, self._analysis_failed, str(error))
            return
        self.root.after(0, self._display_result, result)

    def _analysis_failed(self, error: str) -> None:
        self.open_button.configure(state="normal")
        self.status.set("Analysis failed.")
        messagebox.showerror("Could not analyze capture", f"Check that the file is a readable pcapng capture.\n\n{error}")

    def _display_result(self, result: AnalysisResult) -> None:
        self.result = result
        self.open_button.configure(state="normal")
        self.status.set("Analysis complete. Findings are heuristic leads, not proof of compromise.")
        self.metric_labels["packets"].configure(text=f"{result.packet_count:,}")
        self.metric_labels["duration"].configure(text=f"{result.duration:.1f}s")
        self.metric_labels["volume"].configure(text=self._format_bytes(result.total_bytes))
        self.metric_labels["findings"].configure(text=str(len(result.findings)))
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.findings_by_id.clear()
        for index, finding in enumerate(result.findings):
            item_id = str(index)
            self.findings_by_id[item_id] = finding
            self.findings_tree.insert("", "end", iid=item_id, values=(finding.severity.upper(), finding.title, finding.summary))
        for tree in (self.protocol_tree, self.flow_tree):
            tree.delete(*tree.get_children())
        for name, count in result.protocol_packets.most_common():
            self.protocol_tree.insert("", "end", values=(name, f"{count:,}", self._format_bytes(result.protocol_bytes[name])))
        top_flows = sorted(result.flows.items(), key=lambda item: item[1], reverse=True)[:100]
        for (transport, source, destination, source_port, destination_port), size in top_flows:
            self.flow_tree.insert("", "end", values=(transport, f"{source}:{source_port}", f"{destination}:{destination_port}", self._format_bytes(size)))
        self._draw_chart()

    def _show_finding(self, _event: tk.Event) -> None:
        selection = self.findings_tree.selection()
        if not selection:
            return
        finding = self.findings_by_id[selection[0]]
        text = f"{finding.severity.upper()}  |  {finding.title}\n\n{finding.summary}\n\nEvidence\n{finding.evidence}\n\nSuggested next step\n{finding.recommendation}"
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _draw_chart(self) -> None:
        self.axes.clear()
        self.axes.set_facecolor("#17252c")
        self.axes.tick_params(colors="#91a5ad", labelsize=8)
        for spine in self.axes.spines.values():
            spine.set_color("#34505a")
        self.axes.grid(color="#34505a", alpha=0.45, linewidth=0.7)
        if self.result is None:
            self.axes.text(0.5, 0.5, "Load a capture to generate a graph", ha="center", va="center", color="#91a5ad", transform=self.axes.transAxes)
        elif self.chart_mode.get() == "I/O graph":
            bins = sorted(self.result.io_bins.items())
            if bins:
                origin = self.result.start_time or bins[0][0]
                x_values = [timestamp - origin for timestamp, _ in bins]
                y_values = [size for _, size in bins]
                self.axes.plot(x_values, y_values, color="#59d3b0", linewidth=1.8)
                self.axes.fill_between(x_values, y_values, color="#59d3b0", alpha=0.12)
            self.axes.set_title("Captured bytes per second", color="#e6edf0", loc="left", pad=12)
            self.axes.set_xlabel("Seconds from capture start", color="#91a5ad")
            self.axes.set_ylabel("Bytes", color="#91a5ad")
        else:
            self._draw_flow_graph()
        self.figure.tight_layout(pad=2)
        self.canvas.draw_idle()

    def _draw_flow_graph(self) -> None:
        import networkx as nx

        if self.result is None:
            return
        graph = nx.DiGraph()
        for (transport, source, destination, _source_port, destination_port), size in sorted(self.result.flows.items(), key=lambda item: item[1], reverse=True)[:35]:
            graph.add_edge(source, destination, weight=size, label=f"{transport} {destination_port}")
        if not graph:
            self.axes.text(0.5, 0.5, "No IP flows in this capture", ha="center", va="center", color="#91a5ad", transform=self.axes.transAxes)
            return
        positions = nx.spring_layout(graph, seed=7, k=1.1)
        nx.draw_networkx_nodes(graph, positions, ax=self.axes, node_color="#59d3b0", node_size=800, alpha=0.92)
        nx.draw_networkx_labels(graph, positions, ax=self.axes, font_size=7, font_color="#10211e")
        nx.draw_networkx_edges(graph, positions, ax=self.axes, edge_color="#8ca9b1", arrows=True, arrowsize=12, width=1.2, connectionstyle="arc3,rad=0.08")
        self.axes.set_title("Top 35 directional flows by captured packets", color="#e6edf0", loc="left", pad=12)
        self.axes.axis("off")

    @staticmethod
    def _format_bytes(size: int) -> str:
        value = float(size)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1000 or unit == "TB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1000
        return f"{value:.1f} TB"


def main() -> None:
    root = tk.Tk()
    CaptureAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
