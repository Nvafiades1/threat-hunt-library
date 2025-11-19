<dashboard>
  <label>Ultra Fancy Data Dictionary Explorer</label>

  <!-- ========= GLOBAL INPUTS ========= -->
  <row>
    <panel>
      <!-- Time picker for all sampling -->
      <input type="time" token="time_tok">
        <label>Time range</label>
        <default>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </default>
      </input>

      <!-- Optional: restrict to security indexes -->
      <input type="checkbox" token="sec_only">
        <label>Security indexes only</label>
        <choice value="1">Yes</choice>
        <default>1</default>
      </input>

      <!-- Text filter for field names -->
      <input type="text" token="field_filter">
        <label>Field name contains</label>
        <default></default>
      </input>

      <!-- Radio: how many events to sample for fieldsummary -->
      <input type="radio" token="sample_size">
        <label>Field sample size</label>
        <choice value="2000">2k</choice>
        <choice value="5000">5k</choice>
        <choice value="20000">20k</choice>
        <default>5000</default>
      </input>
    </panel>
  </row>

  <!-- ========= ROW 1: INDEX OVERVIEW / INDEX LIST ========= -->
  <row>
    <panel>
      <title>Indexes overview</title>
      <single>
        <search>
          <query>
            | tstats count where index=* by index
            | eval security = if(match(index,"(winevent|sysmon|corelight|firewall|mde|crowdstrike|suricata|zeek)"),1,0)
            | eval include = if("$sec_only$"="1", security, 1)
            | where include=1
            | stats count as indexes
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="unit">indexes</option>
      </single>
    </panel>

    <panel>
      <title>Total distinct sourcetypes (in filtered indexes)</title>
      <single>
        <search>
          <query>
            | tstats count where index=* by index sourcetype
            | eval security = if(match(index,"(winevent|sysmon|corelight|firewall|mde|crowdstrike|suricata|zeek)"),1,0)
            | eval include = if("$sec_only$"="1", security, 1)
            | where include=1
            | stats dc(sourcetype) as sts
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="unit">sourcetypes</option>
      </single>
    </panel>

    <panel>
      <title>Approx events in selected index/sourcetype</title>
      <single>
        <search>
          <query>
            | tstats count where index="$idx_tok$" sourcetype="$st_tok$"
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="unit">events</option>
      </single>
    </panel>
  </row>

  <row>
    <panel>
      <title>Indexes (click to select)</title>
      <table id="idx_table">
        <search>
          <query>
            | tstats count where index=* by index
            | eval security = if(match(index,"(winevent|sysmon|corelight|firewall|mde|crowdstrike|suricata|zeek)"),1,0)
            | eval include = if("$sec_only$"="1", security, 1)
            | where include=1
            | sort index
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="rowNumbers">false</option>
        <drilldown>
          <set token="idx_tok">$row.index$</set>
          <set token="st_tok">*</set>
          <unset token="field_tok"></unset>
        </drilldown>
      </table>
    </panel>
  </row>

  <!-- ========= ROW 2: SOURCETYPES + HOSTS ========= -->
  <row>
    <panel depends="$idx_tok$">
      <title>Sourcetypes in index: $idx_tok$ (click to select)</title>
      <table id="st_table">
        <search>
          <query>
            | tstats count where index="$idx_tok$" by sourcetype source
            | stats sum(count) as events by sourcetype
            | sort -events
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">15</option>
        <option name="rowNumbers">false</option>
        <drilldown>
          <set token="st_tok">$row.sourcetype$</set>
          <unset token="field_tok"></unset>
        </drilldown>
      </table>
    </panel>

    <panel depends="$idx_tok$">
      <title>Top hosts in index: $idx_tok$</title>
      <table>
        <search>
          <query>
            | tstats count where index="$idx_tok$" by host
            | sort -count
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">15</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>
  </row>

  <!-- ========= ROW 3: FIELD SUMMARY + MATRIX ========= -->
  <row>
    <panel depends="$idx_tok$">
      <title>Fields in index: $idx_tok$ (sourcetype: $st_tok$)</title>
      <table id="field_table">
        <search>
          <query>
            index="$idx_tok$" sourcetype="$st_tok$"
            | head $sample_size$
            | fieldsummary
            | eval pct_null = round(100 * (null_count / total), 1)
            | eval cardinality = case(
                distinct_count &lt;= 5, "Very Low (≤5)",
                distinct_count &lt;= 50, "Low (6–50)",
                distinct_count &lt;= 1000, "Medium (51–1000)",
                distinct_count &lt;= 10000, "High (1001–10000)",
                distinct_count &gt; 10000, "Very High (&gt;10000)"
              )
            | eval _field_filter="$field_filter$"
            | where if(_field_filter=="", 1=1, like(field, "%" . _field_filter . "%"))
            | table field data_type distinct_count cardinality pct_null top values
            | sort field
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">30</option>
        <option name="rowNumbers">false</option>
        <drilldown>
          <set token="field_tok">$row.field$</set>
        </drilldown>
      </table>
    </panel>

    <panel depends="$idx_tok$">
      <title>Field vs Sourcetype presence heatmap (sampled)</title>
      <chart>
        <search>
          <query>
            index="$idx_tok$" sourcetype="$st_tok$"
            | head $sample_size$
            | foreach * [ eval field_name = &lt;&lt;FIELD&gt;&gt; | eval sourcetype = sourcetype ]
            <!-- This is a little hacky; simpler approach below -->
          </query>
        </search>
        <option name="charting.chart">heatmap</option>
      </chart>
    </panel>
  </row>

  <!-- NOTE:
       The heatmap above is intentionally left as a placeholder; doing a full
       dynamic field-vs-sourcetype matrix reliably in simple XML is expensive.
       You can comment that panel out if performance is a concern.
  -->

  <!-- ========= ROW 4: TOP VALUES + RAW EVENTS + OPEN-IN-SEARCH ========= -->
  <row>
    <panel depends="$field_tok$">
      <title>Top values for field: $field_tok$ (index: $idx_tok$, sourcetype: $st_tok$)</title>
      <table>
        <search>
          <query>
            index="$idx_tok$" sourcetype="$st_tok$"
            | top limit=20 "$field_tok$"
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">20</option>
        <option name="rowNumbers">false</option>
      </table>
    </panel>

    <panel depends="$idx_tok$">
      <title>Sample events (click row to open in Search)</title>
      <table>
        <search>
          <query>
            index="$idx_tok$" sourcetype="$st_tok$"
            | fields _time host source sourcetype $field_tok$ _raw
            | sort -_time
            | head 50
          </query>
          <earliest>$time_tok.earliest$</earliest>
          <latest>$time_tok.latest$</latest>
        </search>
        <option name="count">50</option>
        <option name="rowNumbers">false</option>
        <drilldown>
          <!-- Build a Search URL with current index/sourcetype/field -->
          <link target="_blank">
            /app/search/search?q=$esc.url$index="$idx_tok$" sourcetype="$st_tok$" | table _time host source sourcetype $field_tok$ _raw$esc.url$
            &amp;earliest=$time_tok.earliest$&amp;latest=$time_tok.latest$
          </link>
        </drilldown>
      </table>
    </panel>
  </row>

</dashboard>
# threat-hunt-library
