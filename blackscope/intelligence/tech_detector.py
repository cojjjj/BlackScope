import requests


def detect_technologies(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "BlackScope/1.0"
                )
            },
        )

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        html = response.text.lower()
        cookies = response.cookies.get_dict()

        technologies = []

        def add_tech(name, confidence, evidence):
            technologies.append(
                {
                    "name": name,
                    "confidence": confidence,
                    "evidence": evidence,
                }
            )

        server = headers.get("server", "")

        if "cloudflare" in server or "cf-ray" in headers:
            add_tech("Cloudflare", 100, "Cloudflare headers detected")

        if "nginx" in server:
            add_tech("Nginx", 95, "Server header")

        if "apache" in server:
            add_tech("Apache", 95, "Server header")

        if "microsoft-iis" in server:
            add_tech("Microsoft IIS", 95, "Server header")

        if "litespeed" in server:
            add_tech("LiteSpeed", 95, "Server header")

        if "caddy" in server:
            add_tech("Caddy", 90, "Server header")

        if "x-powered-by" in headers:
            powered_by = headers.get("x-powered-by", "")
            add_tech(f"Powered By: {powered_by}", 80, "X-Powered-By header")

        if "wp-content" in html or "wordpress" in html:
            add_tech("WordPress", 95, "HTML source")

        if "drupal" in html:
            add_tech("Drupal", 90, "HTML source")

        if "joomla" in html:
            add_tech("Joomla", 90, "HTML source")

        if "laravel_session" in cookies or "laravel" in html:
            add_tech("Laravel", 90, "Cookie or HTML source")

        if "django" in html or "csrftoken" in cookies:
            add_tech("Django", 85, "Cookie or HTML source")

        if "flask" in html:
            add_tech("Flask", 75, "HTML source")

        if "react" in html or "__react" in html:
            add_tech("React", 80, "HTML source")

        if "vue" in html or "__vue" in html:
            add_tech("Vue.js", 80, "HTML source")

        if "angular" in html or "ng-app" in html:
            add_tech("Angular", 80, "HTML source")

        if "__next" in html or "_next/static" in html:
            add_tech("Next.js", 95, "Next.js static assets")

        if "__nuxt" in html or "_nuxt" in html:
            add_tech("Nuxt.js", 95, "Nuxt.js static assets")

        if "bootstrap" in html:
            add_tech("Bootstrap", 90, "HTML source")

        if "tailwind" in html:
            add_tech("Tailwind CSS", 85, "HTML source")

        if "jquery" in html:
            add_tech("jQuery", 90, "HTML source")

        if "github.io" in html or "githubusercontent" in html:
            add_tech("GitHub Pages / GitHub Assets", 90, "HTML source")

        if "vercel" in headers.get("server", "") or "x-vercel-id" in headers:
            add_tech("Vercel", 100, "Vercel headers")

        if "netlify" in headers.get("server", "") or "x-nf-request-id" in headers:
            add_tech("Netlify", 100, "Netlify headers")

        if "x-amz-cf-id" in headers or "cloudfront" in headers.get("via", ""):
            add_tech("AWS CloudFront", 100, "CloudFront headers")

        unique = {}
        for tech in technologies:
            unique[tech["name"]] = tech

        return {
            "detected": list(unique.values()),
            "count": len(unique),
        }

    except Exception as error:
        return {"error": str(error)}