package org.mort11.lipsync;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.json.JSONException;
import org.json.JSONObject;
import org.mort11.lipsync.error.LipSyncError;
import org.mort11.lipsync.error.TerminatedError;

import android.database.sqlite.SQLiteDatabase;

public class LipSyncServer extends LipSyncBase {

	public LipSyncServer(SQLiteDatabase connection, String secret) {
		super(connection, secret);
	}

	public void listen(ServerSocket sock) {
		while (true) {
			try {
				Socket conn = sock.accept();
				sync(conn);
			} catch (Exception e) {
			}
		}
	}

	@Override
	protected TableAndNeededRecords do_status(Socket sock, String table)
			throws IllegalBlockSizeException, BadPaddingException, IOException,
			JSONException, TerminatedError, LipSyncError {
		TableAndNeededRecords tnr = process_status_message(sock);
		send_status_message(sock, tnr.table);
		return tnr;
	}

	@Override
	protected TableAndNeededRecords process_status_message(Socket sock,
			String table) throws LipSyncError, JSONException {
		JSONObject message = (JSONObject) get_message(sock);
		try {
			update_table(message.getString("table"));
			ArrayList<String> needed_records = new ArrayList<String>();
			for (int i = 0; i < message.getJSONArray("uuids").length(); i++) {
				needed_records.add(message.getJSONArray("uuids").getString(i));
			}
			ArrayList<String> uuid_map = get_uuid_map(table);
			for (String uuid : uuid_map) {
				needed_records.remove(uuid);
			}
			return new TableAndNeededRecords(message.getString("table"),
					needed_records);
		} catch (Exception e) {
			throw new LipSyncError();
		}
	}
}
