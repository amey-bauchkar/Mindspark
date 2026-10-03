"""
Warrant Watch — continuous security-evidence monitoring for the exact dependency
versions of an analysed project.

Orchestration only: re-analysis goes through the existing pipeline
(`jobs.analyze_npm_lock` → graph → evidence providers → decision engine), and this
package decides which differences between the previous and the new decisions are
meaningful enough to raise a security-change event.
"""
