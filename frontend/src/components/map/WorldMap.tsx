'use client';

import React, { useMemo, useState } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin, Globe, Building2, ShieldAlert, Layers, Network } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

type ViewMode = 'type' | 'severity' | 'ports';

interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

interface OpenPort {
  port: number;
  service: string;
  isRisky: boolean;
}

interface Asset {
  id: number;
  value: string;
  type?: string;
  findingsCount?: number;
  maxSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  // Port exposure
  openPortsCount?: number;
  riskyPortsCount?: number;
  openPorts?: OpenPort[];
  // Threat intel flags from new services
  dnsThreat?: boolean;
  urlhausMalicious?: boolean;
  geoLocation?: GeoLocation;
}

interface WorldMapProps {
  assets: Asset[];
  onAssetClick?: (asset: Asset) => void;
  /** Narrow-column mode: no country side panel or legend, shorter map. */
  compact?: boolean;
}

// Country code mapping for common mismatches
const countryCodeMap: Record<string, string> = {
  'USA': 'US',
  'GBR': 'GB',
  'DEU': 'DE',
  'FRA': 'FR',
  'CAN': 'CA',
  'AUS': 'AU',
  'JPN': 'JP',
  'CHN': 'CN',
  'IND': 'IN',
  'BRA': 'BR',
};

export function WorldMap({ assets, onAssetClick, compact = false }: WorldMapProps) {
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [position, setPosition] = useState({ coordinates: [0, 20] as [number, number], zoom: 1 });
  const [highlightedCountryCode, setHighlightedCountryCode] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('severity');

  const geoAssets = useMemo(
    () => assets.filter(asset => asset.geoLocation?.latitude && asset.geoLocation?.longitude),
    [assets]
  );

  // Group assets by country for coloring
  const countryData = useMemo(() => {
    const data: Record<string, { count: number; assets: Asset[]; country: string }> = {};
    geoAssets.forEach(asset => {
      let code = asset.geoLocation?.countryCode || 'Unknown';
      // Normalize country code
      if (countryCodeMap[code]) code = countryCodeMap[code];
      
      if (!data[code]) {
        data[code] = { count: 0, assets: [], country: asset.geoLocation?.country || 'Unknown' };
      }
      data[code].count += 1;
      data[code].assets.push(asset);
    });
    return data;
  }, [geoAssets]);

  // Get all countries sorted by asset count
  const allCountries = useMemo(() => {
    return Object.entries(countryData)
      .map(([code, data]) => ({ code, ...data }))
      .sort((a, b) => b.count - a.count);
  }, [countryData]);

  // Get unique countries count
  const uniqueCountries = Object.keys(countryData).length;
  
  // Total assets with geo
  const totalMappedAssets = geoAssets.length;

  const getCountryFill = (geo: any) => {
    // Try different country code formats
    const geoId = geo.id;
    const iso2 = geo.properties?.ISO_A2;
    const iso3 = geo.properties?.ISO_A3;
    
    // Check various formats
    const count = countryData[geoId]?.count || 
                  countryData[iso2]?.count || 
                  countryData[iso3]?.count ||
                  countryData[countryCodeMap[geoId]]?.count ||
                  0;
    
    const isHovered = hoveredCountry === geoId || hoveredCountry === iso2 || hoveredCountry === iso3;
    const isHighlighted = highlightedCountryCode === geoId || 
                          highlightedCountryCode === iso2 || 
                          highlightedCountryCode === iso3 ||
                          (highlightedCountryCode && countryCodeMap[highlightedCountryCode] === iso2);
    
    if (isHighlighted) return "hsl(45 93% 47%)"; // Gold highlight from table hover
    if (isHovered) return "hsl(217 91% 60%)"; // Bright blue on hover
    
    if (count === 0) return "hsl(220 15% 18%)"; // Dark gray for no assets
    if (count >= 20) return "hsl(199 89% 48%)"; // Bright cyan - many assets
    if (count >= 10) return "hsl(199 80% 40%)"; // Cyan
    if (count >= 5) return "hsl(199 70% 35%)";  // Medium cyan
    if (count >= 2) return "hsl(199 60% 30%)";  // Lighter
    return "hsl(199 50% 25%)";                   // Light cyan - few assets
  };

  const getMarkerColor = (asset: Asset): string => {
    if (viewMode === 'ports') {
      if ((asset.riskyPortsCount ?? 0) > 0) return "hsl(0 85% 52%)";     // red — risky ports open
      if ((asset.openPortsCount ?? 0) >= 10) return "hsl(20 95% 55%)";    // orange — many open ports
      if ((asset.openPortsCount ?? 0) >= 3) return "hsl(38 95% 55%)";     // amber — several open
      if ((asset.openPortsCount ?? 0) >= 1) return "hsl(60 90% 55%)";     // yellow — a few open
      return "hsl(142 76% 45%)";                                           // green — no open ports found
    }
    if (viewMode === 'severity') {
      // Threat intel overrides — highest priority
      if (asset.urlhausMalicious || asset.dnsThreat) return "hsl(0 90% 55%)"; // bright red
      switch (asset.maxSeverity) {
        case 'critical': return "hsl(0 85% 50%)";
        case 'high':     return "hsl(20 95% 55%)";
        case 'medium':   return "hsl(38 95% 55%)";
        case 'low':      return "hsl(60 90% 55%)";
        case 'info':     return "hsl(199 89% 48%)";
        default:         return "hsl(142 76% 45%)";
      }
    }
    // Type-based coloring (original)
    switch (asset.type?.toLowerCase()) {
      case 'domain':     return "hsl(142 76% 45%)";
      case 'subdomain':  return "hsl(199 89% 48%)";
      case 'ip_address': return "hsl(280 80% 60%)";
      default:           return "hsl(48 96% 53%)";
    }
  };

  // Severity / threat intel summary counts
  const threatCounts = useMemo(() => ({
    critical: geoAssets.filter(a => a.maxSeverity === 'critical' || a.maxSeverity === 'high').length,
    medium:   geoAssets.filter(a => a.maxSeverity === 'medium').length,
    threats:  geoAssets.filter(a => a.urlhausMalicious || a.dnsThreat).length,
    clean:    geoAssets.filter(a => !a.maxSeverity && !a.urlhausMalicious && !a.dnsThreat).length,
  }), [geoAssets]);

  // Port exposure summary counts
  const portCounts = useMemo(() => ({
    risky:    geoAssets.filter(a => (a.riskyPortsCount ?? 0) > 0).length,
    many:     geoAssets.filter(a => (a.openPortsCount ?? 0) >= 10).length,
    some:     geoAssets.filter(a => (a.openPortsCount ?? 0) >= 1 && (a.openPortsCount ?? 0) < 10).length,
    none:     geoAssets.filter(a => (a.openPortsCount ?? 0) === 0).length,
    totalOpenPorts: geoAssets.reduce((sum, a) => sum + (a.openPortsCount ?? 0), 0),
  }), [geoAssets]);

  const handleMoveEnd = (position: any) => {
    setPosition(position);
  };

  return (
    <Card className="bg-card border-border">
      <CardHeader className={`flex flex-row items-center justify-between pb-2 ${compact ? 'flex-wrap gap-2' : ''}`}>
        <CardTitle className="text-sm font-medium text-foreground flex items-center gap-2">
          <Globe className="h-4 w-4 text-cyan-400" />
          Global Asset Distribution
        </CardTitle>
        <div className="flex items-center gap-4">
          {/* View mode toggle */}
          <div className="flex items-center gap-1 bg-slate-800 rounded-md p-0.5">
            <Button
              size="sm"
              variant="ghost"
              className={`h-6 px-2 text-xs rounded ${viewMode === 'severity' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              onClick={() => setViewMode('severity')}
            >
              <ShieldAlert className="h-3 w-3 mr-1" />
              Severity
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className={`h-6 px-2 text-xs rounded ${viewMode === 'ports' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              onClick={() => setViewMode('ports')}
            >
              <Network className="h-3 w-3 mr-1" />
              Ports
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className={`h-6 px-2 text-xs rounded ${viewMode === 'type' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
              onClick={() => setViewMode('type')}
            >
              <Layers className="h-3 w-3 mr-1" />
              Type
            </Button>
          </div>
          {/* Legend */}
          <div className={compact ? 'hidden' : 'flex items-center gap-3 text-xs'}>
            {viewMode === 'severity' && (
              <>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-red-500"></span>
                  <span className="text-muted-foreground">Critical/High</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                  <span className="text-muted-foreground">Medium</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-green-500"></span>
                  <span className="text-muted-foreground">Clean</span>
                </div>
              </>
            )}
            {viewMode === 'ports' && (
              <>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-red-500"></span>
                  <span className="text-muted-foreground">Risky ports</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                  <span className="text-muted-foreground">Many open</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-green-500"></span>
                  <span className="text-muted-foreground">No ports</span>
                </div>
              </>
            )}
            {viewMode === 'type' && (
              <>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-green-500"></span>
                  <span className="text-muted-foreground">Domain</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                  <span className="text-muted-foreground">Subdomain</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                  <span className="text-muted-foreground">IP</span>
                </div>
              </>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="flex">
          {/* Map Section - Left */}
          <div className={`relative flex-1 ${compact ? 'h-[300px] rounded-b-lg' : 'h-[400px] rounded-bl-lg'} overflow-hidden bg-slate-950`}>
            <ComposableMap
              projection="geoMercator"
              projectionConfig={{
                scale: 140,
                center: [0, 30],
              }}
              className="w-full h-full"
              style={{ width: '100%', height: '100%' }}
            >
              <ZoomableGroup
                zoom={position.zoom}
                center={position.coordinates}
                onMoveEnd={handleMoveEnd}
              >
                <Geographies geography={geoUrl}>
                  {({ geographies }) =>
                    geographies.map((geo) => {
                      const geoId = geo.id;
                      const iso2 = geo.properties?.ISO_A2;
                      const count = countryData[geoId]?.count || 
                                    countryData[iso2]?.count || 
                                    countryData[countryCodeMap[geoId]]?.count || 0;
                      
                      return (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          fill={getCountryFill(geo)}
                          stroke="hsl(220 20% 25%)"
                          strokeWidth={0.5}
                          onMouseEnter={() => setHoveredCountry(geoId)}
                          onMouseLeave={() => setHoveredCountry(null)}
                          style={{
                            default: { outline: "none", transition: "fill 0.2s" },
                            hover: { outline: "none", cursor: count > 0 ? "pointer" : "default" },
                            pressed: { outline: "none" },
                          }}
                        />
                      );
                    })
                  }
                </Geographies>
                
                {/* Asset markers */}
                {geoAssets.map((asset) => {
                  const color = getMarkerColor(asset);
                  const isThreat = asset.urlhausMalicious || asset.dnsThreat;
                  const isHighSeverity = asset.maxSeverity === 'critical' || asset.maxSeverity === 'high';
                  const hasRiskyPorts = (asset.riskyPortsCount ?? 0) > 0;
                  const showPulse =
                    (viewMode === 'severity' && (isThreat || isHighSeverity)) ||
                    (viewMode === 'ports' && hasRiskyPorts);
                  const r = 4 / position.zoom;

                  // Build a readable tooltip
                  const portSummary = asset.openPorts?.length
                    ? `\nPorts: ${asset.openPorts
                        .slice(0, 8)
                        .map(p => `${p.port}${p.service ? `/${p.service}` : ''}${p.isRisky ? '!' : ''}`)
                        .join(', ')}${(asset.openPorts.length > 8) ? `… +${asset.openPorts.length - 8} more` : ''}`
                    : '';

                  return (
                    <Marker
                      key={asset.id}
                      coordinates={[asset.geoLocation!.longitude, asset.geoLocation!.latitude]}
                      onClick={() => onAssetClick?.(asset)}
                    >
                      <g style={{ cursor: 'pointer' }}>
                        {/* Pulse ring for threats/critical/risky-ports */}
                        {showPulse && (
                          <circle
                            r={r + 3}
                            fill="none"
                            stroke={color}
                            strokeWidth={1 / position.zoom}
                            opacity={0.35}
                          />
                        )}
                        <circle
                          r={r}
                          fill={color}
                          stroke="hsl(220 15% 10%)"
                          strokeWidth={0.8 / position.zoom}
                          opacity={0.92}
                        />
                        <title>
                          {asset.value}
                          {asset.geoLocation?.city && ` — ${asset.geoLocation.city}, ${asset.geoLocation.country}`}
                          {asset.maxSeverity ? `\nSeverity: ${asset.maxSeverity.toUpperCase()} (${asset.findingsCount} findings)` : ''}
                          {(asset.openPortsCount ?? 0) > 0 ? `\nOpen ports: ${asset.openPortsCount}${hasRiskyPorts ? ` (${asset.riskyPortsCount} risky)` : ''}` : ''}
                          {portSummary}
                          {isThreat ? '\nTHREAT INTEL MATCH' : ''}
                        </title>
                      </g>
                    </Marker>
                  );
                })}
              </ZoomableGroup>
            </ComposableMap>

            {/* Stats overlay - bottom left */}
            <div className="absolute bottom-3 left-3 flex flex-col gap-2">
              <div className="text-xs bg-slate-900/90 backdrop-blur px-3 py-2 rounded-lg border border-slate-700">
                <div className="flex items-center gap-2 text-slate-200 font-medium mb-2">
                  <MapPin className="h-3 w-3 text-cyan-400" />
                  {totalMappedAssets} assets · {uniqueCountries} {uniqueCountries === 1 ? 'country' : 'countries'}
                </div>
                {viewMode === 'severity' && (
                  <div className="flex items-center gap-3">
                    {threatCounts.threats > 0 && (
                      <div className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-red-500 ring-1 ring-red-400/40"></span>
                        <span className="text-red-400 font-medium">{threatCounts.threats} threat match</span>
                      </div>
                    )}
                    {threatCounts.critical > 0 && (
                      <div className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                        <span className="text-orange-400">{threatCounts.critical} crit/high</span>
                      </div>
                    )}
                    {threatCounts.medium > 0 && (
                      <div className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                        <span className="text-amber-400">{threatCounts.medium} medium</span>
                      </div>
                    )}
                    <div className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-green-500"></span>
                      <span className="text-green-400">{threatCounts.clean} clean</span>
                    </div>
                  </div>
                )}
                {viewMode === 'ports' && (
                  <div className="flex items-center gap-3">
                    {portCounts.risky > 0 && (
                      <div className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-red-500 ring-1 ring-red-400/40"></span>
                        <span className="text-red-400 font-medium">{portCounts.risky} w/ risky ports</span>
                      </div>
                    )}
                    {portCounts.many > 0 && (
                      <div className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-orange-500"></span>
                        <span className="text-orange-400">{portCounts.many} high-exposure</span>
                      </div>
                    )}
                    <div className="flex items-center gap-1">
                      <span className="w-2 h-2 rounded-full bg-slate-400"></span>
                      <span className="text-slate-400">{portCounts.totalOpenPorts} total open ports</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Zoom controls hint */}
            <div className="absolute top-3 right-3 text-xs text-slate-500">
              Scroll to zoom • Drag to pan
            </div>
          </div>

          {/* Country Table Section - Right */}
          <div className={compact ? 'hidden' : 'w-[280px] h-[400px] border-l border-slate-800 bg-slate-950/50 flex flex-col'}>
            {/* Table Header */}
            <div className="px-4 py-3 border-b border-slate-800 bg-slate-900/50">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
                  <Building2 className="h-4 w-4 text-cyan-400" />
                  Assets by Country
                </div>
                <Badge variant="secondary" className="text-xs bg-cyan-500/20 text-cyan-300 border-0">
                  {uniqueCountries}
                </Badge>
              </div>
            </div>

            {/* Table Content */}
            {allCountries.length > 0 ? (
              <div className="flex-1 overflow-y-auto scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                <div className="divide-y divide-slate-800/50">
                  {allCountries.map((country, index) => {
                    const percentage = totalMappedAssets > 0 
                      ? ((country.count / totalMappedAssets) * 100).toFixed(1) 
                      : '0';
                    
                    return (
                      <div
                        key={country.code}
                        className="px-4 py-2.5 hover:bg-slate-800/50 transition-colors cursor-pointer group"
                        onMouseEnter={() => setHighlightedCountryCode(country.code)}
                        onMouseLeave={() => setHighlightedCountryCode(null)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="text-xs text-slate-500 w-5 text-right font-mono">
                              {index + 1}.
                            </span>
                            <span className="text-sm text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                              {country.country}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <span className="text-xs text-slate-500">
                              {percentage}%
                            </span>
                            <Badge 
                              variant="secondary" 
                              className="text-xs px-2 py-0 h-5 min-w-[36px] justify-center bg-cyan-500/20 text-cyan-300 border-0 group-hover:bg-cyan-500/30"
                            >
                              {country.count}
                            </Badge>
                          </div>
                        </div>
                        {/* Mini progress bar */}
                        <div className="mt-1.5 ml-7 h-1 bg-slate-800 rounded-full overflow-hidden">
                          <div 
                            className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400 rounded-full transition-all duration-300"
                            style={{ width: `${Math.min(100, (country.count / (allCountries[0]?.count || 1)) * 100)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
                <div className="text-center px-4">
                  <Globe className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>No geo-located assets</p>
                  <p className="text-xs mt-1">Enrich assets with IP geolocation</p>
                </div>
              </div>
            )}

            {/* Table Footer with total */}
            {allCountries.length > 0 && (
              <div className="px-4 py-2.5 border-t border-slate-800 bg-slate-900/50">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-400 font-medium">Total</span>
                  <Badge className="bg-cyan-600 text-white border-0 hover:bg-cyan-600">
                    {totalMappedAssets} assets
                  </Badge>
                </div>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default WorldMap;
