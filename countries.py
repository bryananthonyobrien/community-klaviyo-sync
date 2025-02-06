from logs import app_logger
from mappings import country_mappings

def normalize_state(region, country):
    app_logger.info(f"normalize_state({region}, {country})")

    # Normalize inputs to lowercase and strip whitespace
    normalized_region = region.lower().replace("-", " ").strip() if region else None
    normalized_country = country.lower().strip() if country else None

    # Check for country alias match (case-insensitive)
    for country_key, mapping in country_mappings.items():
        if normalized_country in map(str.lower, mapping["aliases"]):  # Make aliases case-insensitive
            # If region is empty, return just the country name and code
            if not normalized_region:
                return None, None, mapping["name"], mapping["code"]

            # Lookup by region name (case-insensitive)
            if normalized_region in {k.lower(): v for k, v in mapping["forward"].items()}:
                state_code = mapping["forward"][normalized_region]
                return state_code, mapping["reverse"][state_code], mapping["name"], mapping["code"]

            # Lookup by abbreviation (case-insensitive)
            reverse_mapping = {k.lower(): v for k, v in mapping["reverse"].items()}
            if normalized_region.upper() in reverse_mapping:
                state_name = reverse_mapping[normalized_region.upper()]
                return normalized_region.upper(), state_name, mapping["name"], mapping["code"]

            # Fallback: If no match found, return country name and code (no region)
            return None, None, mapping["name"], mapping["code"]

    # Default: If no country match found, return the original country name
    return None, None, normalized_country.capitalize() if normalized_country else None, None
