---
title: Analytics Notice
nav_exclude: true
---

# Analytics Notice

The pydepgate documentation site uses [GoatCounter](https://www.goatcounter.com/) for page-view analytics. GoatCounter is [open-source](https://github.com/arp242/goatcounter), does not use cookies, and does not track individual users across sites.

## What this site collects

When you visit a page, GoatCounter records:

- Page path and view count
- Session continuity for up to 8 hours (so that reloading a page does not count as a second visit)
- Referrer URL and campaign parameters

## What this site does not collect

- IP addresses are not stored
- No cookies are set or read
- Individual users are not tracked across sessions or across other sites
- The raw User-Agent header string is not stored

## The pydepgate package

The installed `pydepgate` package collects no analytics and makes no network requests except those you explicitly invoke, such as `pydepgate cvedb fetch` downloading the OSV dataset. The analytics described on this page apply only to this documentation site.
