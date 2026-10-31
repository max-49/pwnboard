"""How many hosts red team currently holds on each team, from PWNBoard's own data."""


def team_access(conn, window_minutes):
    """Return {team_number: hosts that called back in the last `window_minutes`}."""
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT team, COUNT(DISTINCT ip)
            FROM callback_events
            WHERE received_at > NOW() - make_interval(mins => %s) AND team LIKE 'Team %%'
            GROUP BY team
            """,
            (window_minutes,),
        )
        rows = cur.fetchall()
    conn.commit()  # end the read transaction so it does not sit open
    access = {}
    for team, hosts in rows:
        try:
            access[int(team.split()[-1])] = hosts
        except ValueError:
            continue
    return access
