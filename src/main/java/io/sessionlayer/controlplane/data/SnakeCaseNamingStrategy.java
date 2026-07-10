package io.sessionlayer.controlplane.data;

import org.springframework.data.relational.core.mapping.NamingStrategy;
import org.springframework.data.relational.core.mapping.RelationalPersistentProperty;

/**
 * Maps camelCase entity properties to snake_case columns (e.g.
 * {@code connectorKind} -&gt; {@code connector_kind}) so entities stay
 * idiomatic Java while the schema stays idiomatic SQL, without an
 * {@code @Column} annotation on every field. Table and schema names come from
 * each entity's {@code @Table(schema = ..., name = ...)} (the annotation wins
 * over this strategy), so only column naming is overridden here.
 */
public class SnakeCaseNamingStrategy implements NamingStrategy {

	@Override
	public String getColumnName(RelationalPersistentProperty property) {
		return camelToSnake(property.getName());
	}

	private static String camelToSnake(String name) {
		StringBuilder sb = new StringBuilder(name.length() + 8);
		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (Character.isUpperCase(c)) {
				if (i > 0) {
					sb.append('_');
				}
				sb.append(Character.toLowerCase(c));
			} else {
				sb.append(c);
			}
		}
		return sb.toString();
	}
}
