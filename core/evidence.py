class EvidenceCollector:
    def collect_visual(self, station):
        print(f"\n[*] Visual inspection for {station['name']}")
        evidence = {
            "broken_seals": input("Broken security seals? (y/n): ").lower() == 'y',
            "loose_reader": input("Loose card reader? (y/n): ").lower() == 'y',
            "mismatched_parts": input("Mismatched colors/parts? (y/n): ").lower() == 'y',
            "extra_cameras": input("Extra/suspicious cameras? (y/n): ").lower() == 'y',
            "notes": input("Additional notes: ").strip()
        }
        return evidence
