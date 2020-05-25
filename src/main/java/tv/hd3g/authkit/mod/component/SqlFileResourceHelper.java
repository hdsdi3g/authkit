/*
 * This file is part of AuthKit.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * Copyright (C) hdsdi3g for hd3g.tv 2019
 *
 */
package tv.hd3g.authkit.mod.component;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

@Component
public class SqlFileResourceHelper {

	private final Map<String, String> sqlFiles;

	public SqlFileResourceHelper() throws IOException {
		final PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();

		class SqlFile {
			private String name;
			private String content;

			public String getName() {
				return name;
			}

			public String getContent() {
				return content;
			}
		}

		sqlFiles = Arrays.stream(resolver.getResources("classpath*:sql/*.sql")).map(r -> {
			final SqlFile sqlFile = new SqlFile();
			sqlFile.name = r.getFilename();

			try (BufferedReader br = new BufferedReader(
			        new InputStreamReader(r.getInputStream(), UTF_8))) {
				sqlFile.content = br.lines().filter(line -> {
					final var l = line.trim();
					return l.startsWith("--") == false
					       && l.startsWith("//") == false
					       && l.startsWith("#") == false;
				}).collect(Collectors.joining(System.lineSeparator()));
				return sqlFile;
			} catch (final IOException e) {
				throw new UncheckedIOException("Can't load ressource file " + r.getDescription(), e);
			}
		}).collect(Collectors.toUnmodifiableMap(SqlFile::getName, SqlFile::getContent));
	}

	public String getSql(final String filename) {
		return Objects.requireNonNull(sqlFiles.get(filename), "Can't found " + filename + " file");
	}

}
