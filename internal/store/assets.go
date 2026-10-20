package store

import (
	"encoding/json"
	"starruler/internal/model"
)

func (s *Store) CreateAsset(a *model.Asset) (int64, error) {
	vars, _ := json.Marshal(a.Vars)
	if a.Vars == nil {
		vars = []byte("{}")
	}
	res, err := s.db.Exec(`INSERT INTO assets(ip, name, category, sub_type, access_proto, access_port, cred_user, cred_password, vars)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		a.IP, a.Name, a.Category, a.SubType, a.AccessProto, a.AccessPort, a.CredUser, a.CredPassword, string(vars))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateAsset(a *model.Asset) error {
	vars, _ := json.Marshal(a.Vars)
	if a.Vars == nil {
		vars = []byte("{}")
	}
	_, err := s.db.Exec(`UPDATE assets SET ip=?, name=?, category=?, sub_type=?, access_proto=?, access_port=?,
		cred_user=?, cred_password=?, vars=? WHERE id=?`,
		a.IP, a.Name, a.Category, a.SubType, a.AccessProto, a.AccessPort, a.CredUser, a.CredPassword, string(vars), a.ID)
	return err
}

func (s *Store) DeleteAsset(id int64) error {
	_, err := s.db.Exec("DELETE FROM assets WHERE id=?", id)
	return err
}

func (s *Store) ListAssets() ([]model.Asset, error) {
	rows, err := s.db.Query(`SELECT id, ip, name, category, sub_type, access_proto, access_port, cred_user, cred_password, vars FROM assets ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func (s *Store) GetAssetsByIDs(ids []int64) ([]model.Asset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	q := `SELECT id, ip, name, category, sub_type, access_proto, access_port, cred_user, cred_password, vars FROM assets WHERE id IN (`
	args := []any{}
	for i, id := range ids {
		if i > 0 {
			q += ","
		}
		q += "?"
		args = append(args, id)
	}
	q += ")"
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func scanAssets(rows interface{ Next() bool }) ([]model.Asset, error) {
	out := []model.Asset{}
	for rows.Next() {
		var a model.Asset
		var vars string
		var scanErr error
		type scanner interface{ Scan(dest ...any) error }
		r, ok := rows.(scanner)
		if !ok {
			return nil, nil
		}
		if scanErr = r.Scan(&a.ID, &a.IP, &a.Name, &a.Category, &a.SubType, &a.AccessProto, &a.AccessPort,
			&a.CredUser, &a.CredPassword, &vars); scanErr != nil {
			return nil, scanErr
		}
		a.Vars = map[string]string{}
		_ = json.Unmarshal([]byte(vars), &a.Vars)
		out = append(out, a)
	}
	return out, nil
}
