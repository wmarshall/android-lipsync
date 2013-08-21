package org.mort11.lipsync;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.json.JSONException;
import org.json.JSONObject;
import org.mort11.lipsync.error.LipSyncError;
import org.mort11.lipsync.error.SyncError;
import org.mort11.lipsync.error.TerminatedError;

import android.database.sqlite.SQLiteDatabase;
import android.util.Log;

public class LipSyncClient extends LipSyncBase {
	/**
	 * Usable public methods: sync(Socket sock, table)
	 * 
	 * @param connection
	 * @param secret
	 */
	public LipSyncClient(SQLiteDatabase connection, String secret) {
		super(connection, secret);
	}

	@Override
	protected TableAndNeededRecords do_status(Socket sock, String table)
			throws IllegalBlockSizeException, BadPaddingException, IOException,
			JSONException, TerminatedError, LipSyncError {
		Log.d(LogCatTag, "TABLE = " + table);
		update_table(table);
		send_status_message(sock, table);
		TableAndNeededRecords tnr = process_status_message(sock, table);
		return tnr;
	}

	@Override
	protected TableAndNeededRecords process_status_message(Socket sock,
			String table) throws TerminatedError, LipSyncError, JSONException {
		JSONObject message = check_terminated((JSONObject) get_message(sock));
		if (!message.get("table").equals(table)) {
			throw new SyncError();
		}
		ArrayList<String> needed_records = new ArrayList<String>();
		for (int i = 0; i < message.getJSONArray("uuids").length(); i++) {
			needed_records.add(message.getJSONArray("uuids").getString(i));
		}
		ArrayList<String> uuid_map = get_uuid_map(table);
		for (String uuid : uuid_map) {
			needed_records.remove(uuid);
		}
		return new TableAndNeededRecords(table, needed_records);
	}

}
