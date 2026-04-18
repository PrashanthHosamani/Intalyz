import time
from ..core.base_adapter import BaseAdapter
from ..config import settings

class OtxAdapter(BaseAdapter):
    """
    AlienVault OTX integration for passive DNS and threat intelligence.
    Extracts subdomains, IP addresses, and threat pulses.
    """
    
    def __init__(self):
        super().__init__()
        self.api_key = settings.OTX_API_KEY
        self.base_url = "https://otx.alienvault.com/api/v1/indicators/domain/{}/"
        if self.api_key:
            self.session.headers.update({"X-OTX-API-KEY": self.api_key})
            
    def get_name(self) -> str:
        return "otx"

    def fetch(self, entity_name: str, **kwargs) -> dict:
        results = {
            "subdomains": [],
            "ips": [],
            "pulses": [],
            "error": None
        }
        
        if not self.api_key:
            results["error"] = "OTX_API_KEY is not configured."
            return results
            
        candidate_domains = self._candidate_domains(entity_name, kwargs.get("aliases", ""))
        if not candidate_domains:
            results["error"] = "No candidate domains found."
            return results
            
        # We will query passive_dns and general for the best candidate domain
        domain = candidate_domains[0]
        
        time.sleep(settings.RATE_LIMITS.get("otx", 1.0))
        
        try:
            # 1. Passive DNS
            dns_url = self.base_url.format(domain) + "passive_dns"
            dns_resp = self.session.get(dns_url, timeout=10)
            if dns_resp.status_code == 200:
                dns_data = dns_resp.json()
                passive_records = dns_data.get("passive_dns", [])
                subdomains = set()
                ips = set()
                
                for record in passive_records:
                    if record.get("hostname"):
                        subdomains.add(record["hostname"])
                    if record.get("address"):
                        ips.add(record["address"])
                        
                results["subdomains"] = list(subdomains)[:100] # Limit to top 100
                results["ips"] = list(ips)[:100]
                
            # 2. General Pulses (Threat Intel)
            time.sleep(settings.RATE_LIMITS.get("otx", 1.0))
            gen_url = self.base_url.format(domain) + "general"
            gen_resp = self.session.get(gen_url, timeout=10)
            if gen_resp.status_code == 200:
                gen_data = gen_resp.json()
                pulse_info = gen_data.get("pulse_info", {})
                pulses = pulse_info.get("pulses", [])
                
                for pulse in pulses[:5]: # Take top 5 pulses
                    results["pulses"].append({
                        "name": pulse.get("name"),
                        "description": pulse.get("description", ""),
                        "tags": pulse.get("tags", [])
                    })
                    
        except Exception as e:
            results["error"] = str(e)
            
        return results
        
    def _candidate_domains(self, entity_name: str, aliases: str) -> list:
        candidates = []
        if aliases:
            parts = [p.strip() for p in aliases.split(",") if p.strip()]
            for p in parts:
                if "." in p and " " not in p:
                    candidates.append(p.lower())
        
        ent_clean = entity_name.lower().replace(" ", "").replace(",", "")
        if "." in ent_clean:
            candidates.append(ent_clean)
        else:
            candidates.append(f"{ent_clean}.com")
            
        return list(dict.fromkeys(candidates))
