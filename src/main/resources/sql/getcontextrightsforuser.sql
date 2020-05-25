-- This file is part of AuthKit.
-- Licencied under LGPL v3.
-- Copyright (C) hdsdi3g for hd3g.tv 2019
SELECT
    DISTINCT rrc.name
FROM
    RoleRightContext rrc
JOIN
    rrc.roleRight rr
    WITH rr.name = :rightName
JOIN
    rr.role r
JOIN
    r.groups g
JOIN
    g.users u
WHERE
    u.uuid = :userUUID
    AND ((r.onlyforclient IS NOT NULL
            AND r.onlyforclient = :clientAddr)
        OR r.onlyforclient IS NULL)
