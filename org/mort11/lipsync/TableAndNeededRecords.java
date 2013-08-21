package org.mort11.lipsync;

import java.util.ArrayList;

public class TableAndNeededRecords {
	public final String table;
	public final ArrayList<String> needed_records;

	public TableAndNeededRecords(String table, ArrayList<String> needed_records) {
		this.table = table;
		this.needed_records = needed_records;
	}
}
