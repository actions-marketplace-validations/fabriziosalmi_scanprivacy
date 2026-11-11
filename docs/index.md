# scanprivacy documentation

- [Quickstart](quickstart.md): install, first scan, reading the result
- [Rule catalogue](rules.md): every check the engine can emit
- [HTTP API](api.md): endpoints and the limits that protect the host
- [Deployment](deploy.md): Docker, authentication, running it as a service
- [Art. 13 detectors, measured](art13-measurement.md): precision and recall on 21 labelled notices, and what is still missed
- [Repeat mode, measured](repeat-measurement.md): how many findings change between loads of the same page, with the predictions written first
- [Hosting platforms](platforms.md): which platforms cannot close a header finding, and how that is established
- The [README](../README.md) is the long form: method, scope, reproducibility, attestation, known limits

What the engine does not do is as important as what it does. It observes a visitor who has not decided, from one vantage point, passively. It is not legal advice and not a certification. Read "Known limits" in the README before relying on a report.
