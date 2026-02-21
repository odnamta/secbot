export interface DiscoveredRoute {
  url: string;
  source: 'crawl' | 'nextjs' | 'sitemap' | 'file' | 'probe';
  confidence: 'high' | 'medium' | 'low';
}

export interface RouteDiscoverer {
  name: string;
  discover(targetUrl: string): Promise<DiscoveredRoute[]>;
}
