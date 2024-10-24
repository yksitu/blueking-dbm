// Package checker 检查库
package checker

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"dbm-services/mysql/db-tools/mysql-table-checksum/pkg/config"
	"dbm-services/mysql/db-tools/mysql-table-checksum/pkg/reporter"

	_ "github.com/go-sql-driver/mysql" // mysql
	"github.com/jmoiron/sqlx"
)

// NewChecker 新建检查器
func NewChecker(mode config.CheckMode) (*Checker, error) {
	if mode == config.GeneralMode {
		err := os.MkdirAll(config.ChecksumConfig.ReportPath, 0755)
		if err != nil {
			slog.Error("new checker create report path", slog.String("error", err.Error()))
			return nil, err
		}
	}

	checker := &Checker{
		Config:   config.ChecksumConfig,
		reporter: reporter.NewReporter(config.ChecksumConfig),
		Mode:     mode,
	}

	// checker 需要一个序列化器方便打日志

	splitR := strings.Split(checker.Config.PtChecksum.Replicate, ".")
	checker.resultDB = splitR[0]
	checker.resultTbl = splitR[1]
	checker.resultHistoryTable = fmt.Sprintf("%s_history", splitR[1])

	if err := checker.connect(); err != nil {
		slog.Error("connect host", slog.String("error", err.Error()))
		return nil, err
	}

	if err := checker.ptPrecheck(); err != nil {
		return nil, err
	}

	err := checker.prepareReplicateTable()
	if err != nil {
		return nil, err
	}

	checker.applyForceSwitchStrategy(commonForceSwitchStrategies)
	checker.applyDefaultSwitchStrategy(commonDefaultSwitchStrategies)
	checker.applyForceKVStrategy(commonForceKVStrategies)
	checker.applyDefaultKVStrategy(commonDefaultKVStrategies)

	if checker.Mode == config.GeneralMode {
		checker.applyForceSwitchStrategy(generalForceSwitchStrategies)
		checker.applyDefaultSwitchStrategy(generalDefaultSwitchStrategies)
		checker.applyForceKVStrategy(generalForceKVStrategies)
		checker.applyDefaultKVStrategy(generalDefaultKVStrategies)

		if err := checker.validateHistoryTable(); err != nil {
			return nil, err
		}
	} else {
		checker.applyForceSwitchStrategy(demandForceSwitchStrategies)
		checker.applyDefaultSwitchStrategy(demandDefaultSwitchStrategies)
		checker.applyForceKVStrategy(demandForceKVStrategies)
		checker.applyDefaultKVStrategy(demandDefaultKVStrategies)

		if err := checker.validateSlaves(); err != nil {
			return nil, err
		}

		if err := checker.prepareDsnsTable(); err != nil {
			return nil, err
		}
	}

	checker.buildCommandArgs()

	return checker, nil
}

func (r *Checker) connect() (err error) {
	r.db, err = sqlx.Connect(
		"mysql",
		fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s?parseTime=true&loc=%s",
			r.Config.User,
			r.Config.Password,
			r.Config.Ip,
			r.Config.Port,
			r.resultDB,
			time.Local.String(),
		),
	)
	if err != nil {
		slog.Error("connect host", slog.String("error", err.Error()))
		return err
	}

	r.conn, err = r.db.Connx(context.Background())
	if err != nil {
		slog.Error("get conn from sqlx.db", slog.String("error", err.Error()))
		return err
	}
	_, err = r.conn.ExecContext(
		context.Background(), `SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;`)
	if err != nil {
		slog.Error("set transaction isolation level", slog.String("error", err.Error()))
		return err
	}

	_, err = r.conn.ExecContext(context.Background(), `SET BINLOG_FORMAT = 'STATEMENT'`)
	if err != nil {
		slog.Error(
			"set binlog format to statement before insert fake result", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *Checker) validateSlaves() error {
	if len(r.Config.Slaves) < 1 {
		err := fmt.Errorf("demand checksum need at least 1 slave")
		slog.Error("validate slaves counts", slog.String("error", err.Error()))
		return err
	}

	/*
		实际是要能 select 所有库表, 但是权限不好查
		这里只查下能不能连接
	*/
	for _, slave := range r.Config.Slaves {
		_, err := sqlx.Connect(
			"mysql",
			fmt.Sprintf(
				"%s:%s@tcp(%s:%d)/",
				slave.User,
				slave.Password,
				slave.Ip,
				slave.Port,
			),
		)
		if err != nil {
			slog.Error("validate slaves connect", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}

func (r *Checker) prepareReplicateTable() error {
	ctSql := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s (
     master_ip      CHAR(32)     default '0.0.0.0',
     master_port    INT          default 3306,
     db             CHAR(64)     NOT NULL,
     tbl            CHAR(64)     NOT NULL,
     chunk          INT          NOT NULL,
     chunk_time     FLOAT            NULL,
     chunk_index    VARCHAR(200)     NULL,
     lower_boundary BLOB             NULL,
     upper_boundary BLOB             NULL,
     this_crc       CHAR(40)     NOT NULL,
     this_cnt       INT          NOT NULL,
     master_crc     CHAR(40)         NULL,
     master_cnt     INT              NULL,
     ts             TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
     PRIMARY KEY (master_ip, master_port, db, tbl, chunk),
     INDEX db_tbl_chunk (db, tbl, chunk),
     INDEX ts_db_tbl (ts, db, tbl)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;`, r.resultDB, r.resultTbl)
	_, err := r.db.Exec(ctSql)
	if err != nil {
		slog.Error("prepare replicate table error", slog.String("error", err.Error()))
		return err
	}
	return nil
}

func (r *Checker) prepareDsnsTable() error {
	_, err := r.db.Exec(`DROP TABLE IF EXISTS dsns`)
	if err != nil {
		slog.Error("drop exists dsns table", slog.String("error", err.Error()))
		return err
	}

	_, err = r.db.Exec(
		`CREATE TABLE dsns (` +
			`id int NOT NULL AUTO_INCREMENT,` +
			`parent_id int DEFAULT NULL,` +
			`dsn varchar(255) NOT NULL,` +
			`PRIMARY KEY(id)) ENGINE=InnoDB`,
	)
	if err != nil {
		slog.Error("create dsns table", slog.String("error", err.Error()))
		return err
	}

	for _, slave := range r.Config.Slaves {
		_, err := r.conn.ExecContext(
			context.Background(),
			`INSERT INTO dsns (dsn) VALUES (?)`,
			fmt.Sprintf(`h=%s,u=%s,p=%s,P=%d`, slave.Ip, slave.User, slave.Password, slave.Port),
		)
		if err != nil {
			slog.Error("add slave dsn record", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}

func (r *Checker) validateHistoryTable() error {
	r.hasHistoryTable = false

	var _r interface{}
	err := r.db.Get(
		&_r,
		`SELECT 1 FROM INFORMATION_SCHEMA.TABLES `+
			`WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND TABLE_TYPE='BASE TABLE'`,
		r.resultDB,
		r.resultHistoryTable,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Info("history table not found")
			if r.Config.InnerRole == config.RoleSlave {
				slog.Info("no need create history table", slog.String("inner role", string(r.Config.InnerRole)))
				return nil
			} else {
				slog.Info("create history table", slog.String("inner role", string(r.Config.InnerRole)))

				err := r.db.Get(
					&_r,
					`SELECT 1 FROM INFORMATION_SCHEMA.TABLES `+
						`WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND TABLE_TYPE='BASE TABLE'`,
					r.resultDB,
					r.resultTbl,
				)

				if err != nil {
					if errors.Is(err, sql.ErrNoRows) {
						slog.Info("checksum result table not found")
						return nil
					} else {
						slog.Error("try to find checksum result table failed", slog.String("error", err.Error()))
						return err
					}
				}

				// 为了兼容 flashback, 这里拼上库前缀
				_, err = r.db.Exec(
					fmt.Sprintf(
						`CREATE TABLE IF NOT EXISTS %s.%s LIKE %s.%s`,
						r.resultDB,
						r.resultHistoryTable,
						r.resultDB,
						r.resultTbl,
					),
				)
				if err != nil {
					slog.Error("create history table", slog.String("error", err.Error()))
					return err
				}

				// 为了兼容 flashback, 这里拼上库前缀
				_, err = r.db.Exec(
					fmt.Sprintf(
						`ALTER TABLE %s.%s ADD reported int default 0, `+
							`ADD INDEX idx_reported(reported), `+
							`DROP PRIMARY KEY, `+
							`MODIFY ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, `+
							`ADD PRIMARY KEY(master_ip, master_port, db, tbl, chunk, ts)`,
						r.resultDB,
						r.resultHistoryTable,
					),
				)
				if err != nil {
					slog.Error("add column and index to history table", slog.String("error", err.Error()))
					return err
				}
			}
		} else {
			slog.Error("check history table exists", slog.String("error", err.Error()))
			return err
		}
	}
	r.hasHistoryTable = true

	/*
		1. 对比结果表和历史表结构, 历史表应该多出一个 reported int default 0
		2. 历史表主键检查
	*/
	var diffColumn struct {
		TableName       string `db:"TABLE_NAME"`
		ColumnName      string `db:"COLUMN_NAME"`
		OrdinalPosition int    `db:"ORDINAL_POSITION"`
		DataType        string `db:"DATA_TYPE"`
		ColumnType      string `db:"COLUMN_TYPE"`
		RowCount        int    `db:"ROW_COUNT"`
	}
	err = r.db.Get(
		&diffColumn,
		fmt.Sprintf(
			`SELECT `+
				`TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, COLUMN_TYPE, COUNT(1) as ROW_COUNT `+
				`FROM INFORMATION_SCHEMA.COLUMNS WHERE `+
				`TABLE_SCHEMA = '%s' AND TABLE_NAME in ('%s', '%s') `+
				`GROUP BY COLUMN_NAME, ORDINAL_POSITION, DATA_TYPE, COLUMN_TYPE HAVING ROW_COUNT <> 2`,
			r.resultDB,
			r.resultTbl,
			r.resultHistoryTable,
		),
	)
	if err != nil {
		slog.Error("compare result table column", slog.String("error", err.Error()))
		return err
	}

	if diffColumn.TableName != r.resultHistoryTable ||
		diffColumn.ColumnName != "reported" ||
		diffColumn.DataType != "int" {
		err = fmt.Errorf("%s need column as 'reported int default 0'", r.resultHistoryTable)
		slog.Error("check history table reported column", slog.String("error", err.Error()))
		return nil
	}

	var pkColumns []string
	err = r.db.Select(
		&pkColumns,
		fmt.Sprintf(
			`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.STATISTICS `+
				`WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s' AND INDEX_NAME = 'PRIMARY' `+
				`ORDER BY SEQ_IN_INDEX`,
			r.resultDB,
			r.resultHistoryTable,
		),
	)
	if err != nil {
		slog.Error("check history table primary key", slog.String("error", err.Error()))
		return err
	}

	if slices.Compare(pkColumns, []string{"master_ip", "master_port", "db", "tbl", "chunk", "ts"}) != 0 {
		err = fmt.Errorf("history table must has primary as (master_ip, master_port, db, tbl, chunk, ts])")
		slog.Error("check history table primary key", slog.String("error", err.Error()))
		return err
	}

	return nil
}
