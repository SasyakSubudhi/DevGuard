# Architecture

```mermaid
flowchart TD
    A[Bug report and failure log] --> B[IBM Bob IDE]
    B --> C[Log investigation]
    B --> D[Code-path investigation]
    B --> E[Dependency and test investigation]
    C --> F[Evidence synthesis]
    D --> F
    E --> F
    G[Read-only Python evidence collector] --> F
    F --> H[Cited root cause]
    H --> I[Minimal source fix]
    I --> J[Regression test]
    J --> K[Test execution and review]
    K --> L[Validated incident report]
```

Bob owns the reasoning loop, repository changes, regression-test creation, and validation. The Python collector is deterministic support: it scans bounded local inputs concurrently and provides evidence that Bob can compare with its own investigation.
