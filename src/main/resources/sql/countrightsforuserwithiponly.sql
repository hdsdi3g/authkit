-- This file is part of AuthKit.
-- Licencied under LGPL v3.
-- Copyright (C) hdsdi3g for hd3g.tv 2019
SELECT
    COUNT(DISTINCT r.name)
FROM
    Role r
JOIN
    r.groups g
JOIN
    g.users u
WHERE
    u.uuid = :userUUID
    AND r.onlyforclient = :clientAddr
