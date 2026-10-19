import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { useState } from "react";
import { fmtCount, fmtDate, fmtScore, githubUrl } from "../lib/format";
import { TIER_RANK, type DependentRow } from "../lib/graph";
import { ConfidenceBadge, LayerLabel, RelationshipBadge } from "./Badges";

const col = createColumnHelper<DependentRow>();

const columns = [
  col.accessor("id", {
    header: "Repository",
    cell: (c) => (
      <div style={{ minWidth: 200 }}>
        <a
          className="repo"
          href={githubUrl(c.getValue())}
          target="_blank"
          rel="noreferrer"
          onClick={(e) => e.stopPropagation()}
        >
          {c.getValue()}
        </a>
        {c.row.original.description && (
          <div className="desc truncate">{c.row.original.description}</div>
        )}
      </div>
    ),
  }),
  col.accessor((r) => TIER_RANK[r.confidence] * 1000 + r.score, {
    id: "confidence",
    header: "Confidence",
    cell: (c) => (
      <span className="nowrap" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
        <ConfidenceBadge value={c.row.original.confidence} score={c.row.original.score} />
        <span className="faint small mono">{fmtScore(c.row.original.score)}</span>
      </span>
    ),
  }),
  col.accessor("relationship", {
    header: "Relationship",
    cell: (c) => <RelationshipBadge value={c.getValue()} />,
  }),
  col.accessor("layer", {
    header: "Evidence",
    sortUndefined: "last",
    cell: (c) => <span className="nowrap small"><LayerLabel layer={c.getValue()} /></span>,
  }),
  col.accessor("stars", {
    header: "Stars",
    meta: { num: true },
    cell: (c) => fmtCount(c.getValue()),
  }),
  col.accessor("contributors", {
    header: "Contribs",
    meta: { num: true },
    cell: (c) => fmtCount(c.getValue()),
  }),
  col.accessor("matchCount", {
    header: "Matches",
    meta: { num: true },
    cell: (c) => fmtCount(c.getValue()),
  }),
  col.accessor("papersTotal", {
    header: "Papers",
    meta: { num: true },
    cell: (c) =>
      c.getValue() ? (
        <span title={`${c.row.original.papersHigh} high-relevance`}>
          {c.getValue()}
          {c.row.original.papersHigh > 0 && (
            <span className="faint"> · {c.row.original.papersHigh}★</span>
          )}
        </span>
      ) : (
        <span className="faint">0</span>
      ),
  }),
  col.accessor("license", {
    header: "License",
    cell: (c) => <span className="small nowrap">{c.getValue() === "None" ? "—" : c.getValue()}</span>,
  }),
  col.accessor("lastUpdate", {
    header: "Updated",
    cell: (c) => <span className="small nowrap">{fmtDate(c.getValue())}</span>,
  }),
  col.accessor("depth", {
    header: "Depth",
    meta: { num: true },
  }),
];

interface Props {
  rows: DependentRow[];
  selectedId?: string | null;
  onSelect?: (id: string) => void;
  showDepth?: boolean;
}

export function DependentsTable({ rows, selectedId, onSelect, showDepth = true }: Props) {
  const [sorting, setSorting] = useState<SortingState>([{ id: "confidence", desc: true }]);
  // TanStack Table returns non-memoizable helpers by design.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, columnVisibility: { depth: showDepth } },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 100 } },
    autoResetPageIndex: true,
  });

  if (rows.length === 0) return <div className="empty">No dependents match.</div>;

  const { pageIndex } = table.getState().pagination;
  const pageCount = table.getPageCount();

  return (
    <>
      <div className="table-wrap">
        <table className="data">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => {
                  const num = (h.column.columnDef.meta as { num?: boolean } | undefined)?.num;
                  const dir = h.column.getIsSorted();
                  return (
                    <th
                      key={h.id}
                      className={`sortable ${num ? "num" : ""}`}
                      onClick={h.column.getToggleSortingHandler()}
                      aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : "none"}
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                      {dir === "asc" ? " ▲" : dir === "desc" ? " ▼" : ""}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className={row.original.id === selectedId ? "selected" : undefined}
                onClick={() => onSelect?.(row.original.id)}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onSelect?.(row.original.id);
                }}
              >
                {row.getVisibleCells().map((cell) => {
                  const num = (cell.column.columnDef.meta as { num?: boolean } | undefined)?.num;
                  return (
                    <td key={cell.id} className={num ? "num" : undefined}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pageCount > 1 && (
        <div className="row card-pad" style={{ justifyContent: "flex-end", paddingTop: 10, paddingBottom: 10 }}>
          <span className="small muted">
            Page {pageIndex + 1} of {pageCount}
          </span>
          <button className="btn btn-sm" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()}>
            Previous
          </button>
          <button className="btn btn-sm" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()}>
            Next
          </button>
        </div>
      )}
    </>
  );
}
