document.addEventListener("DOMContentLoaded", function () {

    /* =========================================================
       VULNGRAPH - PROFESSIONAL INTERACTIVE DEPENDENCY GRAPH
       ========================================================= */

    if (window.__VULNGRAPH_GRAPH_INITIALIZED__) {
        console.warn("VulnGraph graph already initialized.");
        return;
    }

    window.__VULNGRAPH_GRAPH_INITIALIZED__ = true;


    const graphContainer =
        document.querySelector("#dependency-graph");

    if (!graphContainer) {
        console.error("Dependency graph container not found.");
        return;
    }

    if (typeof graphData === "undefined") {
        console.error("Graph data not found.");
        return;
    }

    console.log("VulnGraph professional graph loaded.");
    console.log("Graph data:", graphData);


    /* =========================================================
       DATA
       ========================================================= */

    const nodes = Array.isArray(graphData.nodes)
        ? graphData.nodes
        : [];

    const edges = Array.isArray(graphData.edges)
        ? graphData.edges
        : [];


    /* =========================================================
       EMPTY GRAPH
       ========================================================= */

    if (nodes.length === 0) {

        graphContainer.innerHTML = `
            <div class="vg-empty">
                <div class="vg-empty-icon">🔗</div>

                <h3>No Dependency Graph Available</h3>

                <p>
                    Upload a valid dependency file to generate
                    the dependency relationship graph.
                </p>
            </div>
        `;

        applyContainerStyle();
        return;
    }


    /* =========================================================
       MAIN GRAPH HTML
       ========================================================= */

    graphContainer.innerHTML = "";

    const graph = document.createElement("div");

    graph.className = "vg-graph";

    graph.innerHTML = `

        <!-- ================= TOOLBAR ================= -->

        <div class="vg-toolbar">

            <div class="vg-toolbar-left">

                <div class="vg-graph-title">
                    <span class="vg-title-icon">🔗</span>
                    Dependency Relationship Map
                </div>

                <div class="vg-graph-subtitle">
                    Project
                    <span>→</span>
                    Direct Dependencies
                    <span>→</span>
                    Transitive Dependencies
                </div>

            </div>


            <div class="vg-toolbar-right">

                <button
                    type="button"
                    class="vg-btn"
                    id="vg-reset">

                    ↻ Reset View

                </button>

            </div>

        </div>


        <!-- ================= LEGEND ================= -->

        <div class="vg-legend">

            <div class="vg-legend-section">

                <span class="vg-legend-heading">
                    Type
                </span>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-project"></span>
                    Project
                </div>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-direct"></span>
                    Direct
                </div>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-transitive"></span>
                    Transitive
                </div>

            </div>


            <div class="vg-legend-divider"></div>


            <div class="vg-legend-section">

                <span class="vg-legend-heading">
                    Risk Status
                </span>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-high"></span>
                    High Risk
                </div>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-medium"></span>
                    Medium Risk
                </div>

                <div class="vg-legend-item">
                    <span class="vg-dot vg-dot-low"></span>
                    Low / Safe
                </div>

            </div>

        </div>


        <!-- ================= GRAPH CANVAS ================= -->

        <div
            class="vg-canvas"
            id="vg-canvas">

            <div class="vg-level-label vg-level-project">
                PROJECT
            </div>

            <div class="vg-level-label vg-level-direct">
                DIRECT DEPENDENCIES
            </div>

            <div class="vg-level-label vg-level-transitive">
                TRANSITIVE DEPENDENCIES
            </div>


            <svg
                class="vg-lines"
                id="vg-lines"
                xmlns="http://www.w3.org/2000/svg">

                <defs>

                    <marker
                        id="vg-arrow"
                        markerWidth="8"
                        markerHeight="8"
                        refX="6"
                        refY="3"
                        orient="auto"
                        markerUnits="strokeWidth">

                        <path
                            d="M0,0 L0,6 L6,3 z"
                            class="vg-arrow-shape">
                        </path>

                    </marker>

                </defs>

            </svg>


            <div
                class="vg-node-layer"
                id="vg-node-layer">
            </div>

        </div>


        <!-- ================= SUMMARY ================= -->

        <div class="vg-summary">

            <div class="vg-summary-card">

                <div class="vg-summary-icon">
                    🧩
                </div>

                <div>

                    <span class="vg-summary-number">
                        ${nodes.length}
                    </span>

                    <span class="vg-summary-label">
                        Total Nodes
                    </span>

                </div>

            </div>


            <div class="vg-summary-card">

                <div class="vg-summary-icon">
                    📦
                </div>

                <div>

                    <span class="vg-summary-number">
                        ${getDirectCount(nodes)}
                    </span>

                    <span class="vg-summary-label">
                        Direct Dependencies
                    </span>

                </div>

            </div>


            <div class="vg-summary-card">

                <div class="vg-summary-icon">
                    🔗
                </div>

                <div>

                    <span class="vg-summary-number">
                        ${getTransitiveCount(nodes)}
                    </span>

                    <span class="vg-summary-label">
                        Transitive Dependencies
                    </span>

                </div>

            </div>


            <div class="vg-summary-card vg-summary-danger">

                <div class="vg-summary-icon">
                    ⚠️
                </div>

                <div>

                    <span class="vg-summary-number vg-risk-number">
                        ${getVulnerableCount(nodes)}
                    </span>

                    <span class="vg-summary-label">
                        Vulnerable Dependencies
                    </span>

                </div>

            </div>

        </div>


        <!-- ================= DETAILS ================= -->

        <div
            class="vg-node-details"
            id="vg-node-details">

            <div class="vg-details-placeholder">

                <div class="vg-placeholder-icon">
                    👆
                </div>

                <strong>
                    Select a dependency
                </strong>

                <p>
                    Click any node above to view
                    vulnerability, risk and trust details.
                </p>

            </div>

        </div>


        <!-- ================= RELATIONSHIPS ================= -->

        <div class="vg-relationships">

            <div class="vg-relationship-heading">

                <div>

                    <span class="vg-section-icon">
                        🔗
                    </span>

                    Dependency Relationships

                </div>


                <span class="vg-edge-count">

                    ${edges.length}
                    relationship${edges.length === 1 ? "" : "s"}

                </span>

            </div>


            <div
                class="vg-relationship-list"
                id="vg-relationship-list">
            </div>

        </div>

    `;

    graphContainer.appendChild(graph);

    applyContainerStyle();


    /* =========================================================
       GET ELEMENTS
       ========================================================= */

    const canvas =
        graph.querySelector("#vg-canvas");

    const nodeLayer =
        graph.querySelector("#vg-node-layer");

    const svg =
        graph.querySelector("#vg-lines");

    const details =
        graph.querySelector("#vg-node-details");

    const relationshipList =
        graph.querySelector("#vg-relationship-list");

    const resetButton =
        graph.querySelector("#vg-reset");


    /* =========================================================
       NODE STORAGE
       ========================================================= */

    const nodeElements = new Map();
    const nodeDataMap = new Map();


    nodes.forEach(node => {

        const id = getNodeId(node);

        if (id) {
            nodeDataMap.set(id, node);
        }

    });


    /* =========================================================
       NODE CATEGORIES
       ========================================================= */

    const projectNode =
        nodes.find(
            node => node.type === "project"
        );


    const directNodes =
        nodes.filter(node =>
            node.type === "dependency" &&
            (
                node.dependency_type === "direct" ||
                node.dependency_type === undefined
            )
        );


    const transitiveNodes =
        nodes.filter(node =>
            node.type === "dependency" &&
            node.dependency_type === "transitive"
        );


    /* =========================================================
       LAYOUT
       ========================================================= */

    const canvasWidth =
        Math.max(
            canvas.clientWidth || 900,
            900
        );


    const directSpacing =
        calculateSpacing(
            directNodes.length,
            canvasWidth
        );


    const transitiveSpacing =
        calculateSpacing(
            transitiveNodes.length,
            canvasWidth
        );


    /* =========================================================
       PROJECT NODE
       ========================================================= */

    if (projectNode) {

        const element =
            createNodeElement(projectNode);

        element.style.left = "50%";
        element.style.top = "58px";
        element.style.transform = "translateX(-50%)";

        nodeLayer.appendChild(element);

        nodeElements.set(
            getNodeId(projectNode),
            element
        );

    }


    /* =========================================================
       DIRECT NODES
       ========================================================= */

    directNodes.forEach(
        (node, index) => {

            const element =
                createNodeElement(node);

            const left =
                calculatePosition(
                    index,
                    directNodes.length,
                    directSpacing
                );

            element.style.left =
                left + "px";

            element.style.top =
                "195px";

            element.style.transform =
                "translateX(-50%)";

            nodeLayer.appendChild(element);

            nodeElements.set(
                getNodeId(node),
                element
            );

        }
    );


    /* =========================================================
       TRANSITIVE NODES
       ========================================================= */

    transitiveNodes.forEach(
        (node, index) => {

            const element =
                createNodeElement(node);

            const left =
                calculatePosition(
                    index,
                    transitiveNodes.length,
                    transitiveSpacing
                );

            element.style.left =
                left + "px";

            element.style.top =
                "350px";

            element.style.transform =
                "translateX(-50%)";

            nodeLayer.appendChild(element);

            nodeElements.set(
                getNodeId(node),
                element
            );

        }
    );


    /* =========================================================
       CLICK HANDLER
       ========================================================= */

    nodeLayer.addEventListener(
        "click",
        function (event) {

            const clickedNode =
                event.target.closest(".vg-node");

            if (!clickedNode) {
                return;
            }

            const nodeId =
                clickedNode.dataset.nodeId;

            const node =
                nodeDataMap.get(nodeId);

            if (!node) {
                console.error(
                    "Node data not found:",
                    nodeId
                );
                return;
            }

            selectNode(
                node,
                clickedNode
            );

        }
    );


    /* =========================================================
       KEYBOARD ACCESSIBILITY
       ========================================================= */

    nodeLayer.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key !== "Enter" &&
                event.key !== " "
            ) {
                return;
            }

            const keyboardNode =
                event.target.closest(".vg-node");

            if (!keyboardNode) {
                return;
            }

            event.preventDefault();

            const nodeId =
                keyboardNode.dataset.nodeId;

            const node =
                nodeDataMap.get(nodeId);

            if (!node) {
                return;
            }

            selectNode(
                node,
                keyboardNode
            );

        }
    );


    /* =========================================================
       HOVER EVENTS
       ========================================================= */

    nodeLayer.addEventListener(
        "mouseover",
        function (event) {

            const hoveredNode =
                event.target.closest(".vg-node");

            if (!hoveredNode) {
                return;
            }

            highlightConnections(
                hoveredNode.dataset.nodeId
            );

        }
    );


    nodeLayer.addEventListener(
        "mouseout",
        function (event) {

            const hoveredNode =
                event.target.closest(".vg-node");

            if (!hoveredNode) {
                return;
            }

            const relatedTarget =
                event.relatedTarget;

            if (
                relatedTarget &&
                hoveredNode.contains(relatedTarget)
            ) {
                return;
            }

            clearConnectionHighlight();

        }
    );


    /* =========================================================
       DRAW CONNECTIONS
       ========================================================= */

    function drawConnections() {

        svg.innerHTML = `
            <defs>

                <marker
                    id="vg-arrow"
                    markerWidth="8"
                    markerHeight="8"
                    refX="6"
                    refY="3"
                    orient="auto"
                    markerUnits="strokeWidth">

                    <path
                        d="M0,0 L0,6 L6,3 z"
                        class="vg-arrow-shape">
                    </path>

                </marker>

            </defs>
        `;


        const canvasRect =
            canvas.getBoundingClientRect();


        edges.forEach(edge => {

            const sourceId =
                String(edge.source ?? "");

            const targetId =
                String(edge.target ?? "");


            const sourceElement =
                nodeElements.get(sourceId);

            const targetElement =
                nodeElements.get(targetId);


            if (
                !sourceElement ||
                !targetElement
            ) {

                console.warn(
                    "Connection skipped:",
                    sourceId,
                    "→",
                    targetId
                );

                return;
            }


            const sourceRect =
                sourceElement.getBoundingClientRect();

            const targetRect =
                targetElement.getBoundingClientRect();


            const x1 =
                sourceRect.left +
                sourceRect.width / 2 -
                canvasRect.left;

            const y1 =
                sourceRect.top +
                sourceRect.height -
                canvasRect.top;

            const x2 =
                targetRect.left +
                targetRect.width / 2 -
                canvasRect.left;

            const y2 =
                targetRect.top -
                canvasRect.top;


            const middleY =
                (y1 + y2) / 2;


            const path =
                document.createElementNS(
                    "http://www.w3.org/2000/svg",
                    "path"
                );


            path.setAttribute(
                "d",
                `
                    M ${x1} ${y1}
                    C ${x1} ${middleY},
                      ${x2} ${middleY},
                      ${x2} ${y2}
                `
            );


            path.setAttribute(
                "marker-end",
                "url(#vg-arrow)"
            );


            path.classList.add("vg-edge");

            path.dataset.source = sourceId;
            path.dataset.target = targetId;


            svg.appendChild(path);

        });

    }


    /* =========================================================
       SELECT NODE
       ========================================================= */

    function selectNode(node, element) {

        document
            .querySelectorAll(
                ".vg-node.active"
            )
            .forEach(item => {
                item.classList.remove("active");
            });


        document
            .querySelectorAll(
                ".vg-node.selected-connected"
            )
            .forEach(item => {
                item.classList.remove(
                    "selected-connected"
                );
            });


        element.classList.add("active");


        const nodeId =
            getNodeId(node);


        highlightSelectedConnections(nodeId);


        const name =
            node.label ||
            node.name ||
            "Unknown Dependency";


        const dependencyType =
            node.dependency_type ||
            (
                node.type === "project"
                    ? "Project"
                    : "Dependency"
            );


        const vulnerabilityCount =
            Number(
                node.vulnerability_count || 0
            );


        const impact =
            node.impact_level ||
            node.impact ||
            "Low";


        const version =
            node.version ||
            node.installed_version ||
            "Version information unavailable";


        const riskScore =
            node.risk_score ??
            node.risk ??
            "N/A";


        const trustScore =
            node.trust_score ??
            node.trust ??
            "N/A";


        const riskStatus =
            getRiskStatus(
                riskScore,
                vulnerabilityCount
            );


        const vulnerabilityText =
            vulnerabilityCount === 0
                ? "No known vulnerabilities"
                : vulnerabilityCount === 1
                    ? "1 vulnerability found"
                    : `${vulnerabilityCount} vulnerabilities found`;


        details.innerHTML = `

            <div class="vg-details-header">

                <div class="vg-details-icon">

                    ${
                        vulnerabilityCount > 0
                            ? "⚠️"
                            : node.type === "project"
                                ? "🛡️"
                                : "📦"
                    }

                </div>


                <div class="vg-details-title-area">

                    <div class="vg-details-name">
                        ${escapeHTML(name)}
                    </div>

                    <div class="vg-details-type">
                        ${escapeHTML(
                            String(dependencyType)
                        )}
                    </div>

                </div>


                ${
                    node.type !== "project"
                        ? `
                            <div class="
                                vg-risk-badge
                                ${riskStatus.className}
                            ">
                                ${riskStatus.label}
                            </div>
                        `
                        : ""
                }

            </div>


            <div class="vg-details-grid">

                <div class="vg-detail-item">

                    <span>
                        📌 Installed Version
                    </span>

                    <strong class="vg-mono">
                        ${escapeHTML(
                            String(version)
                        )}
                    </strong>

                </div>


                <div class="vg-detail-item">

                    <span>
                        🛡️ Vulnerabilities
                    </span>

                    <strong class="${
                        vulnerabilityCount > 0
                            ? "vg-danger-text"
                            : "vg-safe-text"
                    }">

                        ${escapeHTML(
                            vulnerabilityText
                        )}

                    </strong>

                </div>


                <div class="vg-detail-item">

                    <span>
                        💥 Impact Level
                    </span>

                    <strong class="${getImpactClass(impact)}">

                        ${escapeHTML(
                            String(impact)
                        )}

                    </strong>

                </div>


                <div class="vg-detail-item">

                    <span>
                        🔗 Dependency Type
                    </span>

                    <strong>
                        ${escapeHTML(
                            String(dependencyType)
                        )}
                    </strong>

                </div>


                <div class="vg-detail-item">

                    <span>
                        📊 Risk Score
                    </span>

                    <strong class="${getRiskScoreClass(riskScore)}">

                        ${
                            riskScore === "N/A"
                                ? "N/A"
                                : escapeHTML(
                                    String(riskScore)
                                )
                        }

                    </strong>

                </div>


                <div class="vg-detail-item">

                    <span>
                        🤝 Trust Score
                    </span>

                    <strong class="${getTrustScoreClass(trustScore)}">

                        ${
                            trustScore === "N/A"
                                ? "N/A"
                                : escapeHTML(
                                    String(trustScore)
                                )
                        }

                    </strong>

                </div>

            </div>

        `;


        setTimeout(
            function () {

                details.scrollIntoView({
                    behavior: "smooth",
                    block: "nearest"
                });

            },
            50
        );

    }


    /* =========================================================
       RELATIONSHIP LIST
       ========================================================= */

    edges.forEach(edge => {

        const item =
            document.createElement("div");


        item.className =
            "vg-relationship-item";


        const source =
            escapeHTML(
                String(
                    edge.source ||
                    "Unknown"
                )
            );


        const target =
            escapeHTML(
                String(
                    edge.target ||
                    "Unknown"
                )
            );


        const type =
            escapeHTML(
                String(
                    edge.type ||
                    "depends-on"
                )
            );


        item.innerHTML = `

            <span class="vg-rel-source">
                ${source}
            </span>

            <span class="vg-rel-arrow">
                →
            </span>

            <span class="vg-rel-target">
                ${target}
            </span>

            <span class="vg-rel-type">
                ${type}
            </span>

        `;


        relationshipList.appendChild(item);

    });


    if (edges.length === 0) {

        relationshipList.innerHTML = `

            <div class="vg-no-relationships">
                No dependency relationships available.
            </div>

        `;

    }


    /* =========================================================
       RESET
       ========================================================= */

    if (resetButton) {

        resetButton.addEventListener(
            "click",
            function () {

                document
                    .querySelectorAll(
                        ".vg-node.active"
                    )
                    .forEach(item => {
                        item.classList.remove("active");
                    });


                document
                    .querySelectorAll(
                        ".vg-node.selected-connected"
                    )
                    .forEach(item => {
                        item.classList.remove(
                            "selected-connected"
                        );
                    });


                details.innerHTML = `

                    <div class="vg-details-placeholder">

                        <div class="vg-placeholder-icon">
                            👆
                        </div>

                        <strong>
                            Select a dependency
                        </strong>

                        <p>
                            Click any node above to view
                            vulnerability, risk and trust details.
                        </p>

                    </div>

                `;


                clearConnectionHighlight();

            }
        );

    }


    /* =========================================================
       HOVER CONNECTION HIGHLIGHT
       ========================================================= */

    function highlightConnections(nodeId) {

        document
            .querySelectorAll(".vg-edge")
            .forEach(edge => {

                if (
                    edge.dataset.source === nodeId ||
                    edge.dataset.target === nodeId
                ) {

                    edge.classList.add("highlight");
                    edge.classList.remove("dim");

                } else {

                    edge.classList.add("dim");
                    edge.classList.remove("highlight");

                }

            });


        document
            .querySelectorAll(".vg-node")
            .forEach(nodeElement => {

                const currentId =
                    nodeElement.dataset.nodeId;


                if (currentId === nodeId) {

                    nodeElement.classList.remove(
                        "dim-node"
                    );

                    return;
                }


                const connected =
                    edges.some(edge =>

                        (
                            String(edge.source) === nodeId &&
                            String(edge.target) === currentId
                        )

                        ||

                        (
                            String(edge.target) === nodeId &&
                            String(edge.source) === currentId
                        )

                    );


                if (connected) {

                    nodeElement.classList.remove(
                        "dim-node"
                    );

                } else {

                    nodeElement.classList.add(
                        "dim-node"
                    );

                }

            });

    }


    /* =========================================================
       SELECTED CONNECTION HIGHLIGHT
       ========================================================= */

    function highlightSelectedConnections(nodeId) {

        document
            .querySelectorAll(".vg-edge")
            .forEach(edge => {

                if (
                    edge.dataset.source === nodeId ||
                    edge.dataset.target === nodeId
                ) {

                    edge.classList.add("highlight");
                    edge.classList.remove("dim");

                } else {

                    edge.classList.add("dim");
                    edge.classList.remove("highlight");

                }

            });


        document
            .querySelectorAll(".vg-node")
            .forEach(nodeElement => {

                const currentId =
                    nodeElement.dataset.nodeId;


                if (currentId === nodeId) {
                    return;
                }


                const connected =
                    edges.some(edge =>

                        (
                            String(edge.source) === nodeId &&
                            String(edge.target) === currentId
                        )

                        ||

                        (
                            String(edge.target) === nodeId &&
                            String(edge.source) === currentId
                        )

                    );


                if (connected) {

                    nodeElement.classList.add(
                        "selected-connected"
                    );

                }

            });

    }


    /* =========================================================
       CLEAR CONNECTION HIGHLIGHT
       ========================================================= */

    function clearConnectionHighlight() {

        document
            .querySelectorAll(".vg-edge")
            .forEach(edge => {

                edge.classList.remove(
                    "highlight",
                    "dim"
                );

            });


        document
            .querySelectorAll(".vg-node")
            .forEach(nodeElement => {

                nodeElement.classList.remove(
                    "dim-node"
                );

            });

    }


    /* =========================================================
       INITIAL DRAW
       ========================================================= */

    requestAnimationFrame(
        function () {
            drawConnections();
        }
    );


    /* =========================================================
       RESPONSIVE REDRAW
       ========================================================= */

    window.addEventListener(
        "resize",
        function () {
            drawConnections();
        }
    );


    /* =========================================================
       HELPERS
       ========================================================= */

    function getNodeId(node) {

        return String(
            node.id ??
            node.name ??
            node.label ??
            ""
        );

    }


    function calculateSpacing(count, width) {

        if (count <= 1) {
            return width;
        }

        return Math.max(
            180,
            Math.min(
                250,
                width / count
            )
        );

    }


    function calculatePosition(
        index,
        count,
        spacing
    ) {

        if (count === 1) {

            return canvas.clientWidth / 2;

        }


        const totalWidth =
            (count - 1) * spacing;


        const start =
            Math.max(
                120,
                (
                    canvas.clientWidth -
                    totalWidth
                ) / 2
            );


        return (
            start +
            index * spacing
        );

    }


    function getDirectCount(allNodes) {

        return allNodes.filter(
            node =>
                node.dependency_type === "direct"
        ).length;

    }


    function getTransitiveCount(allNodes) {

        return allNodes.filter(
            node =>
                node.dependency_type === "transitive"
        ).length;

    }


    function getVulnerableCount(allNodes) {

        return allNodes.filter(
            node =>
                Number(
                    node.vulnerability_count || 0
                ) > 0
        ).length;

    }


    /* =========================================================
       RISK STATUS
       ========================================================= */

    function getRiskStatus(
        score,
        vulnerabilityCount
    ) {

        if (
            score === null ||
            score === undefined ||
            score === "N/A"
        ) {

            if (
                Number(
                    vulnerabilityCount || 0
                ) > 0
            ) {

                return {
                    label: "Vulnerable",
                    className: "vg-risk-high"
                };

            }


            return {
                label: "Low Risk",
                className: "vg-risk-low"
            };

        }


        const numericScore =
            Number(score);


        if (numericScore >= 70) {

            return {
                label: "High Risk",
                className: "vg-risk-high"
            };

        }


        if (numericScore >= 40) {

            return {
                label: "Medium Risk",
                className: "vg-risk-medium"
            };

        }


        return {
            label: "Low Risk",
            className: "vg-risk-low"
        };

    }


    /* =========================================================
       RISK SCORE CLASS
       ========================================================= */

    function getRiskScoreClass(score) {

        if (
            score === null ||
            score === undefined ||
            score === "N/A"
        ) {
            return "";
        }


        const numericScore =
            Number(score);


        if (numericScore >= 70) {
            return "vg-score-high";
        }


        if (numericScore >= 40) {
            return "vg-score-medium";
        }


        return "vg-score-low";

    }


    /* =========================================================
       TRUST SCORE CLASS
       ========================================================= */

    function getTrustScoreClass(score) {

        if (
            score === null ||
            score === undefined ||
            score === "N/A"
        ) {
            return "";
        }


        const numericScore =
            Number(score);


        if (numericScore >= 80) {
            return "vg-score-low";
        }


        if (numericScore >= 50) {
            return "vg-score-medium";
        }


        return "vg-score-high";

    }


    /* =========================================================
       IMPACT CLASS
       ========================================================= */

    function getImpactClass(impact) {

        const value =
            String(
                impact || ""
            ).toLowerCase();


        if (value === "high") {
            return "vg-score-high";
        }


        if (value === "medium") {
            return "vg-score-medium";
        }


        return "vg-score-low";

    }


    /* =========================================================
       ESCAPE HTML
       ========================================================= */

    function escapeHTML(value) {

        if (
            value === null ||
            value === undefined
        ) {
            return "";
        }


        return String(value)

            .replace(
                /&/g,
                "&amp;"
            )

            .replace(
                /</g,
                "&lt;"
            )

            .replace(
                />/g,
                "&gt;"
            )

            .replace(
                /"/g,
                "&quot;"
            )

            .replace(
                /'/g,
                "&#039;"
            );

    }


    /* =========================================================
       NODE CREATOR
       ========================================================= */

    function createNodeElement(node) {

        const box =
            document.createElement("div");


        box.className = "vg-node";


        const nodeId =
            getNodeId(node);


        box.dataset.nodeId =
            nodeId;


        box.setAttribute(
            "role",
            "button"
        );


        box.setAttribute(
            "tabindex",
            "0"
        );


        const isProject =
            node.type === "project";


        const vulnerabilityCount =
            Number(
                node.vulnerability_count || 0
            );


        const dependencyType =
            node.dependency_type ||
            "dependency";


        const impact =
            node.impact_level ||
            node.impact ||
            "Low";


        const riskScore =
            node.risk_score ??
            node.risk ??
            null;


        const name =
            node.label ||
            node.name ||
            (
                isProject
                    ? "Project"
                    : "Unknown Dependency"
            );


        const riskStatus =
            getRiskStatus(
                riskScore,
                vulnerabilityCount
            );


        /* ================= NODE TYPE ================= */

        if (isProject) {

            box.classList.add(
                "vg-project-node"
            );

        } else {

            if (
                riskStatus.className ===
                "vg-risk-high"
            ) {

                box.classList.add(
                    "vg-high-risk-node"
                );

            } else if (
                riskStatus.className ===
                "vg-risk-medium"
            ) {

                box.classList.add(
                    "vg-medium-risk-node"
                );

            } else {

                box.classList.add(
                    "vg-low-risk-node"
                );

            }

        }


        if (
            dependencyType === "direct"
        ) {

            box.classList.add(
                "vg-direct-node"
            );

        }


        if (
            dependencyType === "transitive"
        ) {

            box.classList.add(
                "vg-transitive-node"
            );

        }


        /* ================= NODE CONTENT ================= */

        box.innerHTML = `

            <div class="vg-node-top">

                <div class="vg-node-icon">

                    ${
                        isProject
                            ? "🛡️"
                            : vulnerabilityCount > 0
                                ? "⚠️"
                                : "📦"
                    }

                </div>


                ${
                    vulnerabilityCount > 0

                        ? `
                            <div class="vg-warning-dot">
                                !
                            </div>
                        `

                        : !isProject

                            ? `
                                <div class="vg-safe-check">
                                    ✓
                                </div>
                            `

                            : ""
                }

            </div>


            <div class="vg-node-name">
                ${escapeHTML(name)}
            </div>


            ${
                isProject

                    ? `

                        <div class="vg-node-type">
                            Root Application
                        </div>

                        <div class="vg-project-status">
                            Dependency Analysis Root
                        </div>

                    `

                    : `

                        <div class="vg-node-type">
                            ${escapeHTML(
                                dependencyType
                            )}
                        </div>

                        <div class="vg-node-version">
                            ${escapeHTML(
                                String(
                                    node.version ||
                                    node.installed_version ||
                                    "Version N/A"
                                )
                            )}
                        </div>

                        <div class="vg-node-vuln">

                            ${
                                vulnerabilityCount > 0

                                    ? `${vulnerabilityCount} Vulnerabilit${vulnerabilityCount === 1 ? "y" : "ies"}`

                                    : "No Known Vulnerabilities"
                            }

                        </div>

                        <div class="vg-node-bottom">

                            <span class="vg-impact-badge">

                                Impact:
                                ${escapeHTML(
                                    String(impact)
                                )}

                            </span>


                            ${
                                riskScore !== null &&
                                riskScore !== undefined

                                    ? `

                                        <span class="
                                            vg-risk-mini
                                            ${getRiskScoreClass(
                                                riskScore
                                            )}
                                        ">

                                            Risk
                                            ${escapeHTML(
                                                String(
                                                    riskScore
                                                )
                                            )}

                                        </span>

                                    `

                                    : ""
                            }

                        </div>

                    `
            }

        `;


        return box;

    }


    /* =========================================================
       INLINE GRAPH STYLING
       ========================================================= */

    function applyContainerStyle() {

        if (
            document.querySelector(
                "#vulngraph-inline-style"
            )
        ) {
            return;
        }


        const style =
            document.createElement("style");


        style.id =
            "vulngraph-inline-style";


        style.textContent = `

            #dependency-graph {
                width: 100%;
                box-sizing: border-box;
            }


            .vg-graph {
                width: 100%;
                box-sizing: border-box;
                font-family: inherit;
                color: #0f172a;
            }


            /* ================= TOOLBAR ================= */

            .vg-toolbar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 20px;
                margin-bottom: 18px;
            }


            .vg-toolbar-left {
                min-width: 0;
            }


            .vg-graph-title {
                font-size: 21px;
                font-weight: 900;
                letter-spacing: -0.3px;
            }


            .vg-title-icon {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 30px;
                height: 30px;
                margin-right: 7px;
                border-radius: 8px;
                background: rgba(37,99,235,0.10);
                vertical-align: middle;
            }


            .vg-graph-subtitle {
                margin-top: 6px;
                font-size: 12px;
                opacity: 0.60;
            }


            .vg-graph-subtitle span {
                margin: 0 5px;
                font-weight: 900;
            }


            .vg-btn {
                border: 1px solid rgba(100,116,139,0.25);
                background: #ffffff;
                border-radius: 9px;
                padding: 9px 15px;
                font-size: 12px;
                font-weight: 800;
                cursor: pointer;
                transition:
                    background 0.2s ease,
                    border-color 0.2s ease,
                    transform 0.2s ease;
            }


            .vg-btn:hover {
                background: #f8fafc;
                border-color: rgba(37,99,235,0.40);
                transform: translateY(-1px);
            }


            /* ================= LEGEND ================= */

            .vg-legend {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 12px 20px;
                padding: 13px 16px;
                margin-bottom: 15px;
                border: 1px solid rgba(100,116,139,0.13);
                border-radius: 11px;
                background: rgba(248,250,252,0.75);
                font-size: 11px;
            }


            .vg-legend-section {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 10px;
            }


            .vg-legend-heading {
                font-size: 9px;
                font-weight: 900;
                text-transform: uppercase;
                letter-spacing: 0.8px;
                opacity: 0.45;
                margin-right: 2px;
            }


            .vg-legend-divider {
                width: 1px;
                height: 20px;
                background: rgba(100,116,139,0.18);
            }


            .vg-legend-item {
                display: flex;
                align-items: center;
                gap: 6px;
                font-weight: 700;
                opacity: 0.75;
            }


            .vg-dot {
                width: 9px;
                height: 9px;
                border-radius: 50%;
                display: inline-block;
                box-shadow: 0 0 0 2px rgba(255,255,255,0.8);
            }


            .vg-dot-project {
                background: #7c3aed;
            }


            .vg-dot-direct {
                background: #2563eb;
            }


            .vg-dot-transitive {
                background: #64748b;
            }


            .vg-dot-high {
                background: #dc2626;
            }


            .vg-dot-medium {
                background: #f59e0b;
            }


            .vg-dot-low {
                background: #16a34a;
            }


            /* ================= CANVAS ================= */

            .vg-canvas {
                position: relative;
                width: 100%;
                min-height: 650px;
                overflow-x: auto;
                overflow-y: hidden;
                border: 1px solid rgba(100,116,139,0.16);
                border-radius: 15px;
                background-color: #f8fafc;

                background-image:
                    linear-gradient(
                        rgba(148,163,184,0.08) 1px,
                        transparent 1px
                    ),
                    linear-gradient(
                        90deg,
                        rgba(148,163,184,0.08) 1px,
                        transparent 1px
                    );

                background-size: 24px 24px;
            }


            .vg-level-label {
                position: absolute;
                left: 16px;
                z-index: 2;
                padding: 4px 7px;
                border-radius: 5px;
                background: rgba(255,255,255,0.82);
                border: 1px solid rgba(100,116,139,0.12);
                font-size: 8px;
                font-weight: 900;
                letter-spacing: 0.8px;
                opacity: 0.42;
                pointer-events: none;
            }


            .vg-level-project {
                top: 50px;
            }


            .vg-level-direct {
                top: 215px;
            }


            .vg-level-transitive {
                top: 430px;
            }


            /* ================= SVG ================= */

            .vg-lines {
                position: absolute;
                inset: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: 1;
                overflow: visible;
            }


            .vg-arrow-shape {
                fill: #94a3b8;
            }


            .vg-edge {
                fill: none;
                stroke: #94a3b8;
                stroke-width: 1.8;
                opacity: 0.48;
                transition:
                    opacity 0.2s ease,
                    stroke-width 0.2s ease,
                    stroke 0.2s ease;

                marker-end: url(#vg-arrow);
            }


            .vg-edge.highlight {
                stroke: #2563eb;
                stroke-width: 3;
                opacity: 1;
            }


            .vg-edge.dim {
                opacity: 0.08;
            }


            /* ================= NODE LAYER ================= */

            .vg-node-layer {
                position: absolute;
                inset: 0;
                z-index: 5;
                pointer-events: none;
            }


            /* ================= BASE NODE ================= */

            .vg-node {
                pointer-events: auto !important;
                position: absolute;
                width: 178px;
                min-height: 142px;
                box-sizing: border-box;
                padding: 13px;
                border-radius: 13px;
                border: 2px solid rgba(100,116,139,0.20);
                background: rgba(255,255,255,0.97);

                box-shadow:
                    0 8px 22px rgba(15,23,42,0.08);

                cursor: pointer !important;
                user-select: none;

                transition:
                    transform 0.2s ease,
                    box-shadow 0.2s ease,
                    border-color 0.2s ease,
                    opacity 0.2s ease,
                    filter 0.2s ease;
            }


            .vg-node:hover {
                transform:
                    translateX(-50%)
                    translateY(-5px)
                    scale(1.025);

                box-shadow:
                    0 16px 35px rgba(15,23,42,0.16);

                z-index: 20;
            }


            .vg-node:focus-visible {
                outline: 3px solid rgba(37,99,235,0.25);
                outline-offset: 2px;
            }


            .vg-node.active {
                border-color: #2563eb !important;

                box-shadow:
                    0 0 0 4px rgba(37,99,235,0.13),
                    0 18px 38px rgba(15,23,42,0.18);

                z-index: 30;
            }


            .vg-node.selected-connected {
                box-shadow:
                    0 0 0 2px rgba(37,99,235,0.18),
                    0 10px 28px rgba(15,23,42,0.12);
            }


            .vg-node.dim-node {
                opacity: 0.28;
                filter: grayscale(0.35);
            }


            /* ================= PROJECT ================= */

            .vg-project-node {
                width: 205px;
                min-height: 125px;
                border-color: #7c3aed;

                background:
                    linear-gradient(
                        145deg,
                        rgba(124,58,237,0.11),
                        rgba(255,255,255,0.98)
                    );

                box-shadow:
                    0 10px 28px rgba(124,58,237,0.12);
            }


            .vg-project-node:hover {
                box-shadow:
                    0 18px 38px rgba(124,58,237,0.18);
            }


            /* ================= RISK ================= */

            .vg-high-risk-node {
                border-color: rgba(220,38,38,0.60);

                background:
                    linear-gradient(
                        145deg,
                        rgba(220,38,38,0.075),
                        rgba(255,255,255,0.98)
                    );
            }


            .vg-medium-risk-node {
                border-color: rgba(245,158,11,0.65);

                background:
                    linear-gradient(
                        145deg,
                        rgba(245,158,11,0.075),
                        rgba(255,255,255,0.98)
                    );
            }


            .vg-low-risk-node {
                border-color: rgba(22,163,74,0.48);

                background:
                    linear-gradient(
                        145deg,
                        rgba(22,163,74,0.06),
                        rgba(255,255,255,0.98)
                    );
            }


            /* ================= DIRECT / TRANSITIVE ================= */

            .vg-direct-node {
                border-left: 5px solid #2563eb;
            }


            .vg-transitive-node {
                border-left: 5px solid #64748b;
            }


            /* ================= NODE CONTENT ================= */

            .vg-node-top {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 7px;
            }


            .vg-node-icon {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 28px;
                height: 28px;
                border-radius: 8px;
                background: rgba(100,116,139,0.08);
                font-size: 17px;
            }


            .vg-warning-dot,
            .vg-safe-check {
                width: 19px;
                height: 19px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                color: #ffffff;
                font-size: 11px;
                font-weight: 900;
            }


            .vg-warning-dot {
                background: #dc2626;

                box-shadow:
                    0 0 0 3px rgba(220,38,38,0.10);
            }


            .vg-safe-check {
                background: #16a34a;

                box-shadow:
                    0 0 0 3px rgba(22,163,74,0.10);
            }


            .vg-node-name {
                font-size: 14px;
                font-weight: 900;
                word-break: break-word;
                line-height: 1.25;
            }


            .vg-node-type {
                display: inline-block;
                margin-top: 5px;
                padding: 3px 6px;
                border-radius: 5px;
                background: rgba(100,116,139,0.08);
                font-size: 8px;
                text-transform: uppercase;
                letter-spacing: 0.7px;
                font-weight: 900;
                opacity: 0.62;
            }


            .vg-node-version {
                margin-top: 7px;
                font-size: 10px;
                font-family: monospace;
                font-weight: 700;
                opacity: 0.68;
                word-break: break-all;
            }


            .vg-node-vuln {
                margin-top: 8px;
                font-size: 10px;
                font-weight: 800;
            }


            .vg-high-risk-node .vg-node-vuln {
                color: #dc2626;
            }


            .vg-medium-risk-node .vg-node-vuln {
                color: #b45309;
            }


            .vg-low-risk-node .vg-node-vuln {
                color: #15803d;
            }


            .vg-node-bottom {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 5px;
                margin-top: 7px;
            }


            .vg-impact-badge {
                font-size: 8px;
                font-weight: 800;
                opacity: 0.62;
            }


            .vg-risk-mini {
                padding: 3px 6px;
                border-radius: 5px;
                font-size: 8px;
                font-weight: 900;
            }


            .vg-score-high {
                color: #dc2626 !important;
            }


            .vg-score-medium {
                color: #b45309 !important;
            }


            .vg-score-low {
                color: #15803d !important;
            }


            .vg-risk-mini.vg-score-high {
                background: rgba(220,38,38,0.09);
            }


            .vg-risk-mini.vg-score-medium {
                background: rgba(245,158,11,0.11);
            }


            .vg-risk-mini.vg-score-low {
                background: rgba(22,163,74,0.09);
            }


            .vg-project-status {
                margin-top: 10px;
                font-size: 9px;
                font-weight: 700;
                opacity: 0.50;
            }


            /* ================= SUMMARY ================= */

            .vg-summary {
                display: grid;
                grid-template-columns:
                    repeat(4, minmax(0,1fr));

                gap: 12px;
                margin-top: 15px;
            }


            .vg-summary-card {
                display: flex;
                align-items: center;
                gap: 11px;
                padding: 14px;
                border-radius: 11px;
                border: 1px solid rgba(100,116,139,0.12);
                background: rgba(248,250,252,0.72);
            }


            .vg-summary-danger {
                border-color:
                    rgba(220,38,38,0.14);

                background:
                    rgba(220,38,38,0.035);
            }


            .vg-summary-icon {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 34px;
                height: 34px;
                flex-shrink: 0;
                border-radius: 9px;
                background: rgba(100,116,139,0.08);
                font-size: 17px;
            }


            .vg-summary-number {
                display: block;
                font-size: 20px;
                font-weight: 900;
                line-height: 1;
            }


            .vg-risk-number {
                color: #dc2626;
            }


            .vg-summary-label {
                display: block;
                margin-top: 4px;
                font-size: 9px;
                font-weight: 700;
                opacity: 0.58;
            }


            /* ================= DETAILS ================= */

            .vg-node-details {
                margin-top: 15px;
                padding: 17px;
                min-height: 135px;
                box-sizing: border-box;
                border-radius: 13px;
                border: 1px solid rgba(100,116,139,0.15);

                background:
                    linear-gradient(
                        145deg,
                        rgba(248,250,252,0.92),
                        rgba(255,255,255,0.96)
                    );
            }


            .vg-details-placeholder {
                min-height: 100px;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                text-align: center;
                opacity: 0.60;
                font-size: 12px;
            }


            .vg-placeholder-icon {
                font-size: 24px;
                margin-bottom: 5px;
            }


            .vg-details-placeholder strong {
                font-size: 12px;
            }


            .vg-details-placeholder p {
                margin: 5px 0 0;
                font-size: 10px;
                opacity: 0.75;
            }


            .vg-details-header {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 15px;
            }


            .vg-details-icon {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 42px;
                height: 42px;
                flex-shrink: 0;
                border-radius: 11px;
                background: rgba(100,116,139,0.08);
                font-size: 22px;
            }


            .vg-details-title-area {
                min-width: 0;
                flex: 1;
            }


            .vg-details-name {
                font-size: 17px;
                font-weight: 900;
                word-break: break-word;
            }


            .vg-details-type {
                margin-top: 3px;
                font-size: 9px;
                opacity: 0.58;
                text-transform: uppercase;
                letter-spacing: 0.7px;
                font-weight: 800;
            }


            .vg-risk-badge {
                padding: 6px 9px;
                border-radius: 7px;
                font-size: 9px;
                font-weight: 900;
                white-space: nowrap;
            }


            .vg-risk-high {
                color: #b91c1c;
                background: rgba(220,38,38,0.10);
            }


            .vg-risk-medium {
                color: #b45309;
                background: rgba(245,158,11,0.12);
            }


            .vg-risk-low {
                color: #15803d;
                background: rgba(22,163,74,0.10);
            }


            .vg-details-grid {
                display: grid;
                grid-template-columns:
                    repeat(3, minmax(0,1fr));

                gap: 10px;
            }


            .vg-detail-item {
                padding: 11px;
                border-radius: 9px;
                border: 1px solid rgba(100,116,139,0.09);
                background: rgba(248,250,252,0.82);
            }


            .vg-detail-item span {
                display: block;
                font-size: 9px;
                opacity: 0.57;
                margin-bottom: 5px;
                font-weight: 700;
            }


            .vg-detail-item strong {
                font-size: 12px;
                word-break: break-word;
            }


            .vg-danger-text {
                color: #dc2626;
            }


            .vg-safe-text {
                color: #16a34a;
            }


            .vg-mono {
                font-family: monospace;
            }


            /* ================= RELATIONSHIPS ================= */

            .vg-relationships {
                margin-top: 15px;
                border-radius: 13px;
                border: 1px solid rgba(100,116,139,0.15);
                overflow: hidden;
                background: #ffffff;
            }


            .vg-relationship-heading {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 13px 15px;
                font-size: 12px;
                font-weight: 900;
                background: rgba(248,250,252,0.85);
            }


            .vg-section-icon {
                margin-right: 5px;
            }


            .vg-edge-count {
                padding: 4px 7px;
                border-radius: 5px;
                background: rgba(100,116,139,0.08);
                font-size: 9px;
                opacity: 0.65;
            }


            .vg-relationship-list {
                max-height: 230px;
                overflow-y: auto;
            }


            .vg-relationship-item {
                display: flex;
                align-items: center;
                flex-wrap: wrap;
                gap: 7px;
                padding: 10px 15px;
                border-top: 1px solid rgba(100,116,139,0.08);
                font-size: 10px;
                transition:
                    background 0.2s ease;
            }


            .vg-relationship-item:hover {
                background: rgba(37,99,235,0.035);
            }


            .vg-rel-source,
            .vg-rel-target {
                font-weight: 800;
                word-break: break-word;
            }


            .vg-rel-arrow {
                font-weight: 900;
                color: #2563eb;
            }


            .vg-rel-type {
                margin-left: auto;
                padding: 3px 7px;
                border-radius: 5px;
                font-size: 8px;
                text-transform: uppercase;
                background: rgba(100,116,139,0.09);
                opacity: 0.70;
                font-weight: 800;
            }


            .vg-no-relationships {
                padding: 18px;
                text-align: center;
                opacity: 0.55;
                font-size: 11px;
            }


            /* ================= EMPTY STATE ================= */

            .vg-empty {
                padding: 50px 20px;
                text-align: center;
                border: 1px dashed rgba(100,116,139,0.25);
                border-radius: 12px;
            }


            .vg-empty-icon {
                font-size: 35px;
                margin-bottom: 10px;
            }


            .vg-empty h3 {
                margin: 0 0 7px;
            }


            .vg-empty p {
                margin: 0;
                opacity: 0.6;
                font-size: 13px;
            }


            /* ================= RESPONSIVE ================= */

            @media (max-width: 900px) {

                .vg-summary {
                    grid-template-columns:
                        repeat(2,minmax(0,1fr));
                }


                .vg-details-grid {
                    grid-template-columns:
                        repeat(2,minmax(0,1fr));
                }


                .vg-canvas {
                    min-width: 900px;
                }

            }


            @media (max-width: 650px) {

                .vg-toolbar {
                    align-items: flex-start;
                    flex-direction: column;
                }


                .vg-legend-divider {
                    display: none;
                }


                .vg-summary {
                    grid-template-columns: 1fr;
                }


                .vg-details-grid {
                    grid-template-columns: 1fr;
                }


                .vg-details-header {
                    align-items: flex-start;
                }


                .vg-risk-badge {
                    margin-left: auto;
                }

            }

        `;


        document.head.appendChild(style);

    }


    console.log(
        "VulnGraph professional graph rendering completed."
    );

});