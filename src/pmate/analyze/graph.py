"""Building the findings graph from the observed context.

The graph is what makes the output composable: a finding is not a line in a
report, it is a node attached to the evidence that produced it, to the legal
provision it hangs from, and to the fix that closes it. Everything a client
needs to answer "why do you say so?" and "what do I do?" is one hop away.

Labels stay neutral — hosts, proper nouns, identifiers, reference keys. The
renderer substitutes translated labels when it draws the diagram.
"""

from __future__ import annotations

from typing import Iterable

from ..core.graph import Graph
from ..core.models import Finding
from .context import Context


def build_graph(ctx: Context, findings: Iterable[Finding]) -> Graph:
    graph = Graph()

    site = graph.node(
        f"site:{ctx.site_domain}",
        "site",
        ctx.site_domain,
        host=ctx.site_host,
        platform=ctx.platform_name,
        title=ctx.obs.title,
        lang=ctx.obs.lang,
        cmp=ctx.cmp_detected,
        tls=(ctx.tls.classification if ctx.tls and ctx.tls.ok else None),
    )
    # one node per page observed, so "loads" says which page loaded what
    for observed in ctx.observed_pages:
        page_node = graph.node(
            f"page:{observed.final_url}",
            "page",
            observed.final_url,
            status=observed.status,
            entry=(observed is ctx.obs),
            headers=sorted(observed.response_headers.keys()) if observed is ctx.obs else [],
        )
        graph.edge(site, page_node, "publishes")
    entry_page = f"page:{ctx.obs.final_url}"

    for fact in ctx.vendors.values():
        vendor = fact.vendor
        vendor_node = graph.node(
            f"vendor:{vendor.id}",
            "vendor",
            vendor.product,
            entity=vendor.vendor,
            entity_key=vendor.vendor_key,
            category=vendor.category,
            jurisdiction=vendor.jurisdiction,
            first_party=fact.first_party,
            consent_class=vendor.consent_class,
            storage_access=vendor.storage_access,
            transfer=fact.transfer,
            transfer_basis=vendor.transfer_basis,
            declared=fact.declared,
            known=vendor.known,
            detected_via=fact.detection,
            pages=list(fact.pages),
        )
        for host in fact.hosts:
            host_node = graph.node(f"host:{host}", "host", host, first_party=fact.first_party)
            for page_url in fact.pages or [ctx.obs.final_url]:
                source = f"page:{page_url}"
                graph.edge(
                    source if graph.has(source) else entry_page,
                    host_node,
                    "loads",
                    resource_types=fact.resource_types,
                )
            graph.edge(host_node, vendor_node, "operated_by")
        if not fact.first_party:
            graph.edge(
                site,
                vendor_node,
                "transfers_to",
                scope=fact.transfer,
                basis=vendor.transfer_basis,
                declared=fact.declared,
                data_types=list(vendor.data_types),
            )

    for fact in ctx.cookies:
        cookie = fact.cookie
        cookie_node = graph.node(
            f"cookie:{cookie.domain}|{cookie.name}",
            "cookie",
            cookie.name,
            domain=cookie.domain,
            data_class=fact.data_class,
            third_party=fact.third_party,
            session=cookie.session,
            secure=cookie.secure,
            http_only=cookie.http_only,
            same_site=cookie.same_site,
        )
        graph.edge(site, cookie_node, "sets", moment="first visit, no interaction")
        if fact.vendor_id and graph.has(f"vendor:{fact.vendor_id}"):
            graph.edge(cookie_node, f"vendor:{fact.vendor_id}", "operated_by")

    for fact in ctx.storage:
        entry = fact.entry
        storage_node = graph.node(
            f"storage:{entry.kind}|{entry.key}",
            "storage",
            entry.key,
            kind=entry.kind,
            data_class=fact.data_class,
            size=entry.size,
        )
        graph.edge(site, storage_node, "sets", moment="first visit, no interaction")

    # only documents actually read become nodes: a probed conventional path that
    # 404s is evidence in the observation, not a document the site publishes
    for doc in ctx.documents:
        if not doc.ok:
            continue
        document_node = graph.node(
            f"document:{doc.url}",
            "document",
            doc.url,
            kind=doc.kind,
            status=doc.status,
            text_len=doc.text_len,
            text_sha256=doc.text_sha256,
            elements=doc.elements,
        )
        graph.edge(site, document_node, "publishes")
        for vendor_id in doc.declared_vendors:
            if graph.has(f"vendor:{vendor_id}"):
                graph.edge(document_node, f"vendor:{vendor_id}", "declares")

    for finding in findings:
        finding_node = graph.node(
            f"finding:{finding.id}",
            "finding",
            finding.id,
            rule=finding.rule_id,
            severity=finding.severity,
            confidence=finding.confidence,
            priority=finding.priority,
            owner=finding.owner,
        )
        subject = finding.subject_node if graph.has(finding.subject_node) else site
        graph.edge(subject, finding_node, "evidences")
        for reference in finding.references:
            obligation = graph.node(f"obligation:{reference}", "obligation", reference)
            graph.edge(finding_node, obligation, "violates")
        if finding.remediation:
            remediation_node = graph.node(
                f"remediation:{finding.id}",
                "remediation",
                finding.remediation.pattern or finding.remediation.key,
                source=finding.remediation.source,
                effort=finding.remediation.effort,
                alternatives=list(finding.remediation.alternatives),
            )
            graph.edge(finding_node, remediation_node, "fixed_by")

    return graph
