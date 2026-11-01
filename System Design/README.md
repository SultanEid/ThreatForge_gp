# ThreatForge — System Design

This directory contains the technical design documentation for **ThreatForge**, a post-incident network security analysis system that processes captured network traffic, identifies suspicious activities, correlates security events, and supports evidence-based attack reconstruction and visualization.

Each document explains the responsibilities, processing methods, data structures, and engineering reasoning behind a specific system component.

## Design Documentation

| Component | Design Document | Description |
|---|---|---|
| Component 1 | The complete details behind the network processing design | Explains PCAP processing, Zeek network measurements, parsing and normalization, observation sampling, feature engineering, asset discovery, and functional role inference. |
| Component 2 | The complete details behind the ML classification design.| Covers dataset preparation, activity-class selection, Random Forest classification, prediction interpretation, Security Event Builder, Event Grouping, and evidence-linked event generation. |
| Component 3 | Event Correlation Design | Describes how Security Events are evaluated and linked using supported network evidence, shared identities, and temporal relationships. |
| Component 4 | Attack Reconstruction Design | Explains how correlated Security Events are organized into evidence-supported activity sequences and relationships. |
| Component 5 | Graphical DSL & Visualization Design | Describes how reconstructed activity is represented through a graphical domain-specific language and presented to users. |

## System Design Overview

ThreatForge is organized into five components with distinct responsibilities:

1. **Component 1 — Network Processing & Feature Extraction:** Converts captured network traffic into structured observations, behavioral features, and asset information.
2. **Component 2 — ML Classification & Security Event Generation:** Classifies network activity and constructs evidence-linked Security Event Candidates.
3. **Component 3 — Event Correlation:** Identifies supported relationships between Security Events.
4. **Component 4 — Attack Reconstruction:** Organizes related events into structured activity sequences while preserving their supporting evidence.
5. **Component 5 — Graphical DSL & Visualization:** Represents reconstructed activity in a structured graphical format for user interpretation.

Together, these components transform historical network captures into structured, explainable security analysis results.

## Repository Structure

```text
System Design/
├── README.md
├── Network Processing Design_Component 1.md
├── ML Classification Design_Component 2.md
├── Event Correlation Design_Component 3.md
├── Attack Reconstruction Design_Component 4.md
└── Graphical DSL Design_Component 5.md
```

## Reading Guide

The documents are organized according to the system's processing flow.

Start with **Component 1** to understand how raw network traffic is processed and represented. Continue with **Component 2** to understand activity classification and Security Event generation.

**Component 3** explains how relationships between Security Events are established. **Component 4** describes how these relationships support attack reconstruction. Finally, **Component 5** covers the graphical representation and visualization of the reconstructed activity.

Each design document can also be read independently to understand the responsibilities and technical design of its corresponding component.
