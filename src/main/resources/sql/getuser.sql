-- This file is part of AuthKit.
-- Licencied under LGPL v3.
-- Copyright (C) hdsdi3g for hd3g.tv 2019
SELECT
    NEW tv.hd3g.authkit.mod.dto.ressource.UserDto(u)
FROM
    User u
WHERE
    u.uuid = :userUUID
    AND u.credential IS NOT NULL
